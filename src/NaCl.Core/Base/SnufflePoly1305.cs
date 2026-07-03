namespace NaCl.Core.Base;

using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using Internal;

/// <summary>
/// An AEAD construction with a <see cref="Snuffle"/> and <see cref="Poly1305"/>, following RFC 8439, section 2.8.
///
/// This implementation produces ciphertext with the following format: {nonce || actual_ciphertext || tag} and only decrypts the same format.
/// </summary>
/// <seealso cref="NaCl.Core.ChaCha20Poly1305" />
/// <seealso cref="NaCl.Core.XChaCha20Poly1305" />
public abstract class SnufflePoly1305 : IDisposable
{
    private readonly Snuffle _snuffle;
    private readonly Snuffle _macKeySnuffle;
    private const int StackallocThreshold = 1024; // 1KB threshold
    public const string AEAD_EXCEPTION_INVALID_TAG = "The tag value could not be verified, or the decryption operation otherwise failed."; // "AEAD Bad Tag Exception";
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SnufflePoly1305"/> class.
    /// </summary>
    /// <param name="key">The secret key.</param>
    protected SnufflePoly1305(ReadOnlyMemory<byte> key)
    {
        _snuffle = CreateSnuffleInstance(key, 1);
        _macKeySnuffle = CreateSnuffleInstance(key, 0);
    }

    /// <summary>
    /// Creates the snuffle instance.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="initialCounter">The initial counter.</param>
    /// <returns>Snuffle.</returns>
    protected abstract Snuffle CreateSnuffleInstance(ReadOnlyMemory<byte> key, int initialCounter);

    /// <summary>
    /// Encrypts the <paramref name="plaintext"/> into the <paramref name="ciphertext"/> destination buffer and computes an authentication tag into a separate buffer with <see cref="Poly1305"/> authentication based on an <paramref name="associatedData"/> and a <paramref name="nonce"/>.
    /// </summary>
    /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
    /// <param name="plaintext">The content to encrypt.</param>
    /// <param name="ciphertext">The byte array to receive the encrypted contents.</param>
    /// <param name="tag">The byte array to receive the generated authentication tag.</param>
    /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
    /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the instance has been disposed.</exception>
    public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = default)
        => Encrypt((ReadOnlySpan<byte>)nonce, (ReadOnlySpan<byte>)plaintext, (Span<byte>)ciphertext, (Span<byte>)tag, (ReadOnlySpan<byte>)associatedData);

    /// <summary>
    /// Encrypts the <paramref name="plaintext"/> into the <paramref name="ciphertext"/> destination buffer and computes an authentication tag into a separate buffer with <see cref="Poly1305"/> authentication based on an <paramref name="associatedData"/> and a <paramref name="nonce"/>.
    /// </summary>
    /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
    /// <param name="plaintext">The content to encrypt.</param>
    /// <param name="ciphertext">The byte span to receive the encrypted contents.</param>
    /// <param name="tag">The byte span to receive the generated authentication tag.</param>
    /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
    /// <exception cref="CryptographicException">Thrown when encryption fails.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the instance has been disposed.</exception>
    public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
    {
        ThrowIfDisposed();

        _snuffle.Encrypt(plaintext, nonce, ciphertext);

        var aadPaddedLen = GetPaddedLength(associatedData, Poly1305.MAC_TAG_SIZE_IN_BYTES);
        var ciphertextPaddedLen = GetPaddedLength(ciphertext, Poly1305.MAC_TAG_SIZE_IN_BYTES);
        var macDataSize = aadPaddedLen + ciphertextPaddedLen + Poly1305.MAC_TAG_SIZE_IN_BYTES;

        // Use stackalloc for small buffers, pooled memory for larger ones
        if (macDataSize <= StackallocThreshold)
        {
            Span<byte> macData = stackalloc byte[macDataSize];
            macData.Clear(); // Ensure padding is zero
            PrepareMacDataRfc8439(macData, associatedData, aadPaddedLen, ciphertext, ciphertextPaddedLen);
            ComputeMacWithPooledKey(nonce, macData, tag);
        }
        else
        {
            // Use pooled memory for larger buffers to avoid stack overflow
            using var macDataOwner = MemoryPool<byte>.Shared.Rent(macDataSize);
            var macData = macDataOwner.Memory.Span[..macDataSize];
            macData.Clear(); // Ensure padding is zero
            PrepareMacDataRfc8439(macData, associatedData, aadPaddedLen, ciphertext, ciphertextPaddedLen);
            ComputeMacWithPooledKey(nonce, macData, tag);
        }
    }

    /// <summary>
    /// Decrypts the <paramref name="ciphertext"/> into the <paramref name="plaintext"/> provided destination buffer if the authentication <paramref name="tag"/> can be validated.
    /// </summary>
    /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
    /// <param name="ciphertext">The encrypted content to decrypt.</param>
    /// <param name="tag">The authentication tag produced for this message during encryption.</param>
    /// <param name="plaintext">The byte array to receive the decrypted contents.</param>
    /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
    /// <exception cref="CryptographicException">The tag value could not be verified, or the decryption operation otherwise failed.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the instance has been disposed.</exception>
    public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = default)
        => Decrypt((ReadOnlySpan<byte>)nonce, (ReadOnlySpan<byte>)ciphertext, (ReadOnlySpan<byte>)tag, (Span<byte>)plaintext, (ReadOnlySpan<byte>)associatedData);

    /// <summary>
    /// Decrypts the <paramref name="ciphertext"/> into the <paramref name="plaintext"/> provided destination buffer if the authentication <paramref name="tag"/> can be validated.
    /// </summary>
    /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
    /// <param name="ciphertext">The encrypted content to decrypt.</param>
    /// <param name="tag">The authentication tag produced for this message during encryption.</param>
    /// <param name="plaintext">The byte span to receive the decrypted contents.</param>
    /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
    /// <exception cref="CryptographicException">The tag value could not be verified, or the decryption operation otherwise failed.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the instance has been disposed.</exception>
    public void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        ThrowIfDisposed();

        if (nonce.IsEmpty || nonce.Length != _snuffle.NonceSizeInBytes)
            throw new ArgumentException(Snuffle.FormatNonceLengthExceptionMessage(_snuffle.GetType().Name, nonce.Length, _snuffle.NonceSizeInBytes));

        if (tag.Length != Poly1305.MAC_TAG_SIZE_IN_BYTES)
            throw new CryptographicException($"The tag length in bytes must be {Poly1305.MAC_TAG_SIZE_IN_BYTES}, but got {tag.Length}.");

        try
        {
            var aadPaddedLen = GetPaddedLength(associatedData, Poly1305.MAC_TAG_SIZE_IN_BYTES);
            var ciphertextPaddedLen = GetPaddedLength(ciphertext, Poly1305.MAC_TAG_SIZE_IN_BYTES);
            var macDataSize = aadPaddedLen + ciphertextPaddedLen + Poly1305.MAC_TAG_SIZE_IN_BYTES;

            // Use stackalloc for small buffers, pooled memory for larger ones
            if (macDataSize <= StackallocThreshold)
            {
                Span<byte> macData = stackalloc byte[macDataSize];
                macData.Clear(); // Ensure padding is zero
                PrepareMacDataRfc8439(macData, associatedData, aadPaddedLen, ciphertext, ciphertextPaddedLen);
                VerifyMacWithPooledKey(nonce, macData, tag);
            }
            else
            {
                // Use pooled memory for larger buffers to avoid stack overflow
                using var macDataOwner = MemoryPool<byte>.Shared.Rent(macDataSize);
                var macData = macDataOwner.Memory.Span[..macDataSize];
                macData.Clear(); // Ensure padding is zero
                PrepareMacDataRfc8439(macData, associatedData, aadPaddedLen, ciphertext, ciphertextPaddedLen);
                VerifyMacWithPooledKey(nonce, macData, tag);
            }
        }
        catch (Exception ex)
        {
            throw new CryptographicException(AEAD_EXCEPTION_INVALID_TAG, ex);
        }

        _snuffle.Decrypt(ciphertext, nonce, plaintext);
    }

    /// <summary>
    /// The MAC key is the first 32 bytes of the first key stream block.
    /// Uses pooled memory to avoid allocations.
    /// </summary>
    /// <param name="nonce">The nonce.</param>
    /// <param name="macKey">The span to receive the MAC key.</param>
    private void GetMacKeyPooled(ReadOnlySpan<byte> nonce, Span<byte> macKey)
    {
        using var blockOwner = MemoryPool<byte>.Shared.Rent(_macKeySnuffle.BlockSizeInBytes);
        var firstBlock = blockOwner.Memory.Span[.._macKeySnuffle.BlockSizeInBytes];
        try
        {
            _macKeySnuffle.ProcessKeyStreamBlock(nonce, 0, firstBlock);
            firstBlock[..Poly1305.MAC_KEY_SIZE_IN_BYTES].CopyTo(macKey);
        }
        finally
        {
            CryptoBytes.Wipe(firstBlock); // Wipe the key stream block before the buffer returns to the shared pool
        }
    }

    /// <summary>
    /// Computes MAC using pooled memory for the key.
    /// </summary>
    /// <param name="nonce">The nonce.</param>
    /// <param name="macData">The MAC data.</param>
    /// <param name="tag">The computed tag.</param>
    private void ComputeMacWithPooledKey(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> macData, Span<byte> tag)
    {
        Span<byte> macKey = stackalloc byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
        try
        {
            GetMacKeyPooled(nonce, macKey);
            Poly1305.ComputeMac(macKey, macData, tag);
        }
        finally
        {
            CryptoBytes.Wipe(macKey); // Clear sensitive data
        }
    }

    /// <summary>
    /// Verifies MAC using pooled memory for the key.
    /// </summary>
    /// <param name="nonce">The nonce.</param>
    /// <param name="macData">The MAC data.</param>
    /// <param name="tag">The tag to verify.</param>
    private void VerifyMacWithPooledKey(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> macData, ReadOnlySpan<byte> tag)
    {
        Span<byte> macKey = stackalloc byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
        try
        {
            GetMacKeyPooled(nonce, macKey);
            Poly1305.VerifyMac(macKey, macData, tag);
        }
        finally
        {
            CryptoBytes.Wipe(macKey); // Clear sensitive data
        }
    }

    /// <summary>
    /// Prepares the input to MAC, following RFC 8439, section 2.8.
    /// </summary>
    /// <param name="mac">The resulting mac content.</param>
    /// <param name="aad">The associated data.</param>
    /// <param name="aadPaddedLen">The associated data padded length.</param>
    /// <param name="ciphertext">The ciphertext.</param>
    /// <param name="ciphertextPaddedLen">The ciphertext padded length.</param>
    private static void PrepareMacDataRfc8439(Span<byte> mac, ReadOnlySpan<byte> aad, int aadPaddedLen, ReadOnlySpan<byte> ciphertext, int ciphertextPaddedLen)
    {
        // Mac Text
        aad.CopyTo(mac[..aad.Length]);
        ciphertext.CopyTo(mac.Slice(aadPaddedLen, ciphertext.Length));

        // Mac Length
        SetMacLength(mac, aadPaddedLen + ciphertextPaddedLen, aad.Length);
        SetMacLength(mac, aadPaddedLen + ciphertextPaddedLen + sizeof(ulong), ciphertext.Length);
    }

    private static int GetPaddedLength(ReadOnlySpan<byte> input, int size) => (input.Length % size == 0) ? input.Length : (input.Length + size - input.Length % size);

    private static void SetMacLength(Span<byte> macData, int offset, int value) => ArrayUtils.StoreUInt64LittleEndian(macData, offset, (ulong)value);

    /// <summary>
    /// Throws an <see cref="ObjectDisposedException"/> if the instance has been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the instance has been disposed.</exception>
    private void ThrowIfDisposed()
    {
#if NET7_0_OR_GREATER
#pragma warning disable IDE0022 // Use expression body for method
        ObjectDisposedException.ThrowIf(_disposed, this);
#pragma warning restore IDE0022 // Use expression body for method
#else
        if (_disposed)
            throw new ObjectDisposedException(GetType().Name);
#endif
    }

    /// <summary>
    /// Releases all resources used by the current instance of <see cref="SnufflePoly1305"/>.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the unmanaged resources used by the <see cref="SnufflePoly1305"/> and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            // Dispose the underlying Snuffle instances which will clear their keys
            _snuffle.Dispose();
            _macKeySnuffle.Dispose();
        }

        _disposed = true;
    }
}
