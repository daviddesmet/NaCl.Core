namespace NaCl.Core.Base;

using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
#if NET6_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
#endif

/// <summary>
/// Abstract base class for XSalsa20, ChaCha20, XChaCha20 and their variants.
/// </summary>
/// <remarks>
/// Variants of Snuffle have two differences: the size of the nonce and the block function that
/// produces a key stream block from a key, a nonce, and a counter. Subclasses of this class
/// specifying these two information by overriding <see cref="NaCl.Core.Base.Snuffle.NonceSizeInBytes" /> and <see cref="NaCl.Core.Base.Snuffle.BlockSizeInBytes" /> and <see cref="NaCl.Core.Base.Snuffle.ProcessKeyStreamBlock(ReadOnlySpan{byte},int,Span{byte})" />.
///
/// Concrete implementations of this class are meant to be used to construct an AEAD with <see cref="NaCl.Core.Poly1305" />. The
/// base class of these AEAD constructions is <see cref="NaCl.Core.Base.SnufflePoly1305" />.
/// For example, <see cref="NaCl.Core.XChaCha20" /> is a subclass of this class and a
/// concrete Snuffle implementation, and <see cref="NaCl.Core.XChaCha20Poly1305" /> is
/// a subclass of <see cref="NaCl.Core.Base.SnufflePoly1305" /> and a concrete AEAD construction.
/// </remarks>
/// <seealso cref="NaCl.Core.Poly1305" />
/// <seealso cref="NaCl.Core.Base.SnufflePoly1305" />
/// <seealso cref="NaCl.Core.ChaCha20" />
/// <seealso cref="NaCl.Core.ChaCha20Poly1305" />
/// <seealso cref="NaCl.Core.XChaCha20" />
/// <seealso cref="NaCl.Core.XChaCha20Poly1305" />
public abstract class Snuffle : IDisposable
{
    private bool _disposed;
    private readonly byte[] _key;

    protected const int KEY_SIZE_IN_INTS = 8;
    public const int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
    protected const int BLOCK_SIZE_IN_INTS = 16;
    public const int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4; // 64

    protected static uint[] SIGMA = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]; // "expand 32-byte k" (4 words constant: "expa", "nd 3", "2-by", and "te k")

    protected ReadOnlyMemory<byte> Key => _key;

    protected readonly int InitialCounter;

    /// <summary>
    /// Initializes a new instance of the <see cref="Snuffle"/> class.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="initialCounter">The initial counter.</param>
    /// <exception cref="CryptographicException">Thrown when the key length is invalid.</exception>
    protected Snuffle(ReadOnlyMemory<byte> key, int initialCounter)
    {
        if (key.Length != KEY_SIZE_IN_BYTES)
            throw new CryptographicException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

        // Make a private copy of the key for secure disposal
        _key = key.ToArray();
        InitialCounter = initialCounter;
    }

    /// <summary>
    /// Process the key stream <paramref name="block"/> from <paramref name="nonce"/> and <paramref name="counter"/>.
    ///
    /// From this function, the Snuffle encryption function can be constructed using the counter
    /// mode of operation. For example, the ChaCha20 block function and how it can be used to
    /// construct the ChaCha20 encryption function are described in section 2.3 and 2.4 of RFC 8439.
    /// </summary>
    /// <param name="nonce">The nonce.</param>
    /// <param name="counter">The counter.</param>
    /// <param name="block">The stream block.</param>
    /// <returns>ByteBuffer.</returns>
    public abstract void ProcessKeyStreamBlock(ReadOnlySpan<byte> nonce, int counter, Span<byte> block);

    /// <summary>
    /// The size of the nonce in bytes.
    /// Salsa20 uses an 8-byte (64-bit) nonce, ChaCha20 uses a 12-byte (96-bit) nonce, but XSalsa20 and XChaCha20 use a 24-byte (192-bit) nonce.
    /// </summary>
    /// <returns>System.Int32.</returns>
    public abstract int NonceSizeInBytes { get; }

    /// <summary>
    /// The size of the stream block in bytes.
    /// </summary>
    public virtual int BlockSizeInBytes => BLOCK_SIZE_IN_BYTES;

    /// <summary>
    /// Encrypts the <paramref name="plaintext"/> into the <paramref name="ciphertext"/> destination buffer using the associated <paramref name="nonce"/>.
    /// </summary>
    /// <param name="plaintext">The content to encrypt.</param>
    /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
    /// <param name="ciphertext">The byte array to receive the encrypted contents.</param>
    /// <exception cref="ArgumentException">Thrown when plaintext and ciphertext lengths don't match, or nonce length is invalid.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the instance has been disposed.</exception>
    public void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
    {
        ThrowIfDisposed();

        if (plaintext.Length != ciphertext.Length)
            throw new ArgumentException("The plaintext parameter and the ciphertext do not have the same length.");

        if (nonce.IsEmpty || nonce.Length != NonceSizeInBytes)
            throw new ArgumentException(FormatNonceLengthExceptionMessage(GetType().Name, nonce.Length, NonceSizeInBytes));

        Process(nonce, ciphertext, plaintext);
    }

    /// <summary>
    /// Decrypts the <paramref name="ciphertext"/> into the <paramref name="plaintext"/> provided destination buffer using the associated <paramref name="nonce"/>.
    /// </summary>
    /// <param name="ciphertext">The encrypted content to decrypt.</param>
    /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
    /// <param name="plaintext">The byte span to receive the decrypted contents.</param>
    /// <exception cref="ArgumentException">Thrown when plaintext and ciphertext lengths don't match, or nonce length is invalid.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when the instance has been disposed.</exception>
    public void Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext)
    {
        ThrowIfDisposed();

        if (plaintext.Length != ciphertext.Length)
            throw new ArgumentException("The ciphertext parameter and the plaintext do not have the same length.");

        if (nonce.IsEmpty || nonce.Length != NonceSizeInBytes)
            throw new ArgumentException(FormatNonceLengthExceptionMessage(GetType().Name, nonce.Length, NonceSizeInBytes));

        Process(nonce, plaintext, ciphertext);
    }

    /// <summary>
    /// Processes the Encryption/Decryption function.
    /// </summary>
    /// <param name="nonce">The nonce.</param>
    /// <param name="output">The output.</param>
    /// <param name="input">The input.</param>
    /// <param name="offset">The output's starting offset.</param>
    private void Process(ReadOnlySpan<byte> nonce, Span<byte> output, ReadOnlySpan<byte> input, int offset = 0)
    {
        var length = input.Length;
        var numBlocks = (length / BlockSizeInBytes) + 1;

        /*
         * Allocates 64 bytes more than below impl as per the benchmarks...
         *
        var block = new byte[BLOCK_SIZE_IN_BYTES];
        for (var i = 0; i < numBlocks; i++)
        {
            ProcessKeyStreamBlock(nonce, i + InitialCounter, block);

            if (i == numBlocks - 1)
                Xor(output, input, block, length % BLOCK_SIZE_IN_BYTES, offset, i); // last block
            else
                Xor(output, input, block, BLOCK_SIZE_IN_BYTES, offset, i);

            CryptoBytes.Wipe(block); // Array.Clear(block, 0, block.Length);
        }
        */

        using var owner = MemoryPool<byte>.Shared.Rent(BlockSizeInBytes);
        for (var i = 0; i < numBlocks; i++)
        {
            ProcessKeyStreamBlock(nonce, i + InitialCounter, owner.Memory.Span);

            if (i == numBlocks - 1)
                Xor(output, input, owner.Memory.Span, length % BlockSizeInBytes, offset, i); // last block
            else
                Xor(output, input, owner.Memory.Span, BlockSizeInBytes, offset, i);

            owner.Memory.Span.Clear();
        }
    }

    /// <summary>
    /// Formats the nonce length exception message.
    /// </summary>
    /// <param name="name">The crypto primitive name.</param>
    /// <param name="actual">The actual nonce length.</param>
    /// <param name="expected">The expected nonce length.</param>
    /// <returns>System.String.</returns>
    internal static string FormatNonceLengthExceptionMessage(string name, int actual, int expected) => $"{name} uses {expected * 8}-bit nonces, but got a {actual * 8}-bit nonce. The nonce length in bytes must be {expected}.";

    /// <summary>
    /// Throws an <see cref="ObjectDisposedException"/> if the instance has been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">Thrown when the instance has been disposed.</exception>
    protected void ThrowIfDisposed()
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
    /// Releases all resources used by the current instance of <see cref="Snuffle"/>.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the unmanaged resources used by the <see cref="Snuffle"/> and optionally releases the managed resources.
    /// </summary>
    /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            // Clear the key from memory
#if NET6_0_OR_GREATER
            CryptographicOperations.ZeroMemory(_key);
#else
            Array.Clear(_key, 0, _key.Length);
#endif
        }

        _disposed = true;
    }

    /// <summary>
    /// XOR the specified output.
    /// </summary>
    /// <param name="output">The output.</param>
    /// <param name="input">The input.</param>
    /// <param name="block">The key stream block.</param>
    /// <param name="len">The length.</param>
    /// <param name="offset">The output's starting offset.</param>
    /// <param name="curBlock">The current block number.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Xor(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> block, int len, int offset, int curBlock)
    {
        var blockOffset = curBlock * BlockSizeInBytes;

#if NET6_0_OR_GREATER
        XorVectorized(output, input, block, len, offset + blockOffset, blockOffset);
#else
        XorScalar(output, input, block, len, offset + blockOffset, blockOffset);
#endif
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void XorScalar(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> block, int len, int outputOffset, int inputOffset)
    {
        for (var i = 0; i < len; i++)
            output[outputOffset + i] = (byte)(input[inputOffset + i] ^ block[i]);
    }

#if NET6_0_OR_GREATER
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void XorVectorized(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> block, int len, int outputOffset, int inputOffset)
    {
        var i = 0;

        fixed (byte* outputPtr = output)
        fixed (byte* inputPtr = input)
        fixed (byte* blockPtr = block)
        {
            if (Avx2.IsSupported && len >= Vector256<byte>.Count)
            {
                var vectorSize = Vector256<byte>.Count; // 32 bytes
                for (; i + vectorSize <= len; i += vectorSize)
                {
                    var inputVec = Avx.LoadVector256(inputPtr + inputOffset + i);
                    var blockVec = Avx.LoadVector256(blockPtr + i);
                    var result = Avx2.Xor(inputVec, blockVec);
                    Avx.Store(outputPtr + outputOffset + i, result);
                }
            }
            else if (Sse2.IsSupported && len >= Vector128<byte>.Count)
            {
                var vectorSize = Vector128<byte>.Count; // 16 bytes
                for (; i + vectorSize <= len; i += vectorSize)
                {
                    var inputVec = Sse2.LoadVector128(inputPtr + inputOffset + i);
                    var blockVec = Sse2.LoadVector128(blockPtr + i);
                    var result = Sse2.Xor(inputVec, blockVec);
                    Sse2.Store(outputPtr + outputOffset + i, result);
                }
            }
            else if (AdvSimd.IsSupported && len >= Vector128<byte>.Count)
            {
                var vectorSize = Vector128<byte>.Count; // 16 bytes
                for (; i + vectorSize <= len; i += vectorSize)
                {
                    var inputVec = AdvSimd.LoadVector128(inputPtr + inputOffset + i);
                    var blockVec = AdvSimd.LoadVector128(blockPtr + i);
                    var result = AdvSimd.Xor(inputVec, blockVec);
                    AdvSimd.Store(outputPtr + outputOffset + i, result);
                }
            }
        }

        // Handle remaining bytes with scalar XOR
        for (; i < len; i++)
            output[outputOffset + i] = (byte)(input[inputOffset + i] ^ block[i]);
    }
#endif
}
