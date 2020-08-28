namespace NaCl.Core.Base
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Security.Cryptography;

    using Internal;

    /// <summary>
    /// An AEAD construction with a <see cref="Snuffle"/> and <see cref="Poly1305"/>, following RFC 8439, section 2.8.
    ///
    /// This implementation produces ciphertext with the following format: {nonce || actual_ciphertext || tag} and only decrypts the same format.
    /// </summary>
    public abstract class SnufflePoly1305
    {
        private readonly Snuffle _snuffle;
        private readonly Snuffle _macKeySnuffle;
        public const string AEAD_EXCEPTION_INVALID_TAG = "The tag value could not be verified, or the decryption operation otherwise failed."; // "AEAD Bad Tag Exception";

        /// <summary>
        /// Initializes a new instance of the <see cref="SnufflePoly1305"/> class.
        /// </summary>
        /// <param name="key">The secret key.</param>
        public SnufflePoly1305(ReadOnlyMemory<byte> key)
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
        /// Encrypts the <paramref name="plaintext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="associatedData"> and a random auto-generated nonce.
        /// </summary>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="associatedData">The optional associated data.</param>
        /// <returns>The encrypted contents.</returns>
        /// <exception cref="CryptographicException">plaintext</exception>
#if !NETSTANDARD1_6
        [ExcludeFromCodeCoverage]
#endif
        [Obsolete("This method will be removed in a future update", true)]
        public virtual byte[] Encrypt(byte[] plaintext, byte[] associatedData = null) => Encrypt((ReadOnlySpan<byte>)plaintext, (ReadOnlySpan<byte>)associatedData);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="associatedData"> and a random auto-generated nonce.
        /// </summary>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="associatedData">The optional associated data.</param>
        /// <returns>The encrypted contents.</returns>
        /// <exception cref="CryptographicException">plaintext</exception>
#if !NETSTANDARD1_6
        [ExcludeFromCodeCoverage]
#endif
        [Obsolete("This method will be removed in a future update", true)]
        public virtual byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        {
            //if (plaintext.Length > int.MaxValue - _snuffle.NonceSizeInBytes() - Poly1305.MAC_TAG_SIZE_IN_BYTES)
            //    throw new ArgumentException($"The {nameof(plaintext)} is too long.");

            var nonce = new byte[_snuffle.NonceSizeInBytes];
            RandomNumberGenerator.Create().GetBytes(nonce);

            var ciphertext = Encrypt(nonce, plaintext, associatedData);

            // return nonce.Concat(ciphertext).ToArray(); // could be inefficient
            return CryptoBytes.Combine(nonce, ciphertext);
        }

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="associatedData"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="associatedData">The associated data.</param>
        /// <returns>The encrypted contents.</returns>
        /// <exception cref="CryptographicException">plaintext</exception>
#if !NETSTANDARD1_6
        [ExcludeFromCodeCoverage]
#endif
        [Obsolete("This method will be removed in a future update", true)]
        public virtual byte[] Encrypt(byte[] nonce, byte[] plaintext, byte[] associatedData = null) => Encrypt((ReadOnlySpan<byte>)nonce, (ReadOnlySpan<byte>)plaintext, (ReadOnlySpan<byte>)associatedData);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="associatedData"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="associatedData">The associated data.</param>
        /// <returns>The encrypted contents.</returns>
        /// <exception cref="CryptographicException">plaintext</exception>
#if !NETSTANDARD1_6
        [ExcludeFromCodeCoverage]
#endif
        [Obsolete("This method will be removed in a future update", true)]
        public virtual byte[] Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        {
            //if (plaintext.Length > int.MaxValue - _snuffle.NonceSizeInBytes() - Poly1305.MAC_TAG_SIZE_IN_BYTES)
            //    throw new ArgumentException($"The {nameof(plaintext)} is too long.");

            var ciphertext = _snuffle.Encrypt(plaintext, nonce);

            var tag = Poly1305.ComputeMac(GetMacKey(nonce), GetMacDataRfc8439(associatedData, ciphertext));

            // Array.Resize(ref ciphertext, ciphertext.Length + Poly1305.MAC_TAG_SIZE_IN_BYTES);
            // Array.Copy(tag, 0, ciphertext, ciphertext.Length - Poly1305.MAC_TAG_SIZE_IN_BYTES, tag.Length);

            // return ciphertext;
            // return ciphertext.Concat(tag).ToArray(); // could be inefficient
            return CryptoBytes.Combine(ciphertext, tag);
        }

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> into the <paramref name="ciphertext"> destination buffer and computes an authentication tag into a separate buffer with <see cref="Poly1305"/> authentication based on an <paramref name="associatedData"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="ciphertext">The byte array to receive the encrypted contents.</param>
        /// <param name="tag">The byte array to receive the generated authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
        /// <exception cref="CryptographicException">plaintext or nonce</exception>
        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = default)
            => Encrypt((ReadOnlySpan<byte>)nonce, (ReadOnlySpan<byte>)plaintext, (Span<byte>)ciphertext, (Span<byte>)tag, (ReadOnlySpan<byte>)associatedData);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> into the <paramref name="ciphertext"> destination buffer and computes an authentication tag into a separate buffer with <see cref="Poly1305"/> authentication based on an <paramref name="associatedData"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="ciphertext">The byte span to receive the encrypted contents.</param>
        /// <param name="tag">The byte span to receive the generated authentication tag.</param>
        /// <param name="associatedData">Extra data associated with this message, which must also be provided during decryption.</param>
        /// <exception cref="CryptographicException">plaintext or nonce</exception>
        public void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> associatedData = default)
        {
            //if (plaintext.Length > int.MaxValue - _snuffle.NonceSizeInBytes() - Poly1305.MAC_TAG_SIZE_IN_BYTES)
            //    throw new ArgumentException($"The {nameof(plaintext)} is too long.");

            _snuffle.Encrypt(plaintext, nonce, ciphertext);
            Poly1305.ComputeMac(GetMacKey(nonce), GetMacDataRfc8439(associatedData, ciphertext), tag);
        }

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="associatedData">.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="associatedData">The optional associated data.</param>
        /// <returns>The decrypted contents.</returns>
        /// <exception cref="CryptographicException"></exception>
#if !NETSTANDARD1_6
        [ExcludeFromCodeCoverage]
#endif
        [Obsolete("This method will be removed in a future update", true)]
        public virtual byte[] Decrypt(byte[] ciphertext, byte[] associatedData = null) => Decrypt((ReadOnlySpan<byte>)ciphertext, (ReadOnlySpan<byte>)associatedData);

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="associatedData">.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="associatedData">The optional associated data.</param>
        /// <returns>The decrypted contents.</returns>
        /// <exception cref="CryptographicException"></exception>
#if !NETSTANDARD1_6
        [ExcludeFromCodeCoverage]
#endif
        [Obsolete("This method will be removed in a future update", true)]
        public virtual byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData = default)
        {
            if (ciphertext.Length < _snuffle.NonceSizeInBytes + Poly1305.MAC_TAG_SIZE_IN_BYTES)
                throw new ArgumentException($"The {nameof(ciphertext)} is too short.");

            return Decrypt(ciphertext.Slice(0, _snuffle.NonceSizeInBytes), ciphertext.Slice(_snuffle.NonceSizeInBytes), associatedData);
        }

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an <paramref name="associatedData"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <returns>The decrypted contents.</returns>
        /// <exception cref="CryptographicException"></exception>
#if !NETSTANDARD1_6
        [ExcludeFromCodeCoverage]
#endif
        [Obsolete("This method will be removed in a future update", true)]
        public virtual byte[] Decrypt(byte[] nonce, byte[] ciphertext, byte[] associatedData = null) => Decrypt((ReadOnlySpan<byte>)nonce, (ReadOnlySpan<byte>)ciphertext, (ReadOnlySpan<byte>)associatedData);

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an <paramref name="associatedData"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <returns>The decrypted contents.</returns>
        /// <exception cref="CryptographicException"></exception>
#if !NETSTANDARD1_6
        [ExcludeFromCodeCoverage]
#endif
        [Obsolete("This method will be removed in a future update", true)]
        public virtual byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData = default)
        {
            if (ciphertext.Length + nonce.Length < _snuffle.NonceSizeInBytes + Poly1305.MAC_TAG_SIZE_IN_BYTES)
                throw new ArgumentException($"The {nameof(ciphertext)} is too short.");

            if (nonce.IsEmpty || nonce.Length != _snuffle.NonceSizeInBytes)
                throw new ArgumentException(_snuffle.FormatNonceLengthExceptionMessage(_snuffle.GetType().Name, nonce.Length, _snuffle.NonceSizeInBytes));

            var limit = ciphertext.Length - Poly1305.MAC_TAG_SIZE_IN_BYTES;

            try
            {
                Poly1305.VerifyMac(GetMacKey(nonce), GetMacDataRfc8439(associatedData, ciphertext.Slice(0, limit)), ciphertext.Slice(limit, Poly1305.MAC_TAG_SIZE_IN_BYTES));
            }
            catch (Exception ex)
            {
                throw new CryptographicException(AEAD_EXCEPTION_INVALID_TAG, ex);
            }

            return _snuffle.Decrypt(ciphertext.Slice(0, limit), nonce);
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"> into the <paramref name="plaintext"> provided destination buffer if the authentication <paramref name="tag"> can be validated.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="tag">The authentication tag produced for this message during encryption.</param>
        /// <param name="plaintext">The byte array to receive the decrypted contents.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <exception cref="CryptographicException">The tag value could not be verified, or the decryption operation otherwise failed.</exception>
        public virtual void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = default)
            => Decrypt((ReadOnlySpan<byte>)nonce, (ReadOnlySpan<byte>)ciphertext, (ReadOnlySpan<byte>)tag, (Span<byte>)plaintext, (ReadOnlySpan<byte>)associatedData);

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"> into the <paramref name="plaintext"> provided destination buffer if the authentication <paramref name="tag"> can be validated.
        /// </summary>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="tag">The authentication tag produced for this message during encryption.</param>
        /// <param name="plaintext">The byte span to receive the decrypted contents.</param>
        /// <param name="associatedData">Extra data associated with this message, which must match the value provided during encryption.</param>
        /// <exception cref="CryptographicException">The tag value could not be verified, or the decryption operation otherwise failed.</exception>
        public virtual void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        {
            if (nonce.IsEmpty || nonce.Length != _snuffle.NonceSizeInBytes)
                throw new ArgumentException(_snuffle.FormatNonceLengthExceptionMessage(_snuffle.GetType().Name, nonce.Length, _snuffle.NonceSizeInBytes));

            try
            {
                Poly1305.VerifyMac(GetMacKey(nonce), GetMacDataRfc8439(associatedData, ciphertext), tag);
            }
            catch (Exception ex)
            {
                throw new CryptographicException(AEAD_EXCEPTION_INVALID_TAG, ex);
            }

            _snuffle.Decrypt(ciphertext, nonce, plaintext);
        }

        /// <summary>
        /// The MAC key is the first 32 bytes of the first key stream block.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        private Span<byte> GetMacKey(ReadOnlySpan<byte> nonce)
        {
            //var firstBlock = new byte[Snuffle.BLOCK_SIZE_IN_BYTES];
            //_macKeySnuffle.ProcessKeyStreamBlock(nonce, 0, firstBlock);

            //var result = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
            //Array.Copy(firstBlock, result, result.Length);
            //return result;

            Span<byte> firstBlock = new byte[Snuffle.BLOCK_SIZE_IN_BYTES];
            _macKeySnuffle.ProcessKeyStreamBlock(nonce, 0, firstBlock);

            return firstBlock.Slice(0, Poly1305.MAC_KEY_SIZE_IN_BYTES);
        }

        /// <summary>
        /// Prepares the input to MAC, following RFC 8439, section 2.8.
        /// </summary>
        /// <param name="aad">The associated data.</param>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <returns>System.Byte[].</returns>
        [ThreadStatic]
        private static byte[] macDataBytes = new byte[0];
        private ReadOnlySpan<byte> GetMacDataRfc8439(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext)
        {
            var aadPaddedLen = (aad.Length % 16 == 0) ? aad.Length : (aad.Length + 16 - aad.Length % 16);
            var ciphertextLen = ciphertext.Length;
            var ciphertextPaddedLen = (ciphertextLen % 16 == 0) ? ciphertextLen : (ciphertextLen + 16 - ciphertextLen % 16);
            var macDataLength = aadPaddedLen + ciphertextPaddedLen + 16;

            if (macDataBytes.Length < macDataLength)
                macDataBytes = new byte[macDataLength];

            Span<byte> macData = macDataBytes;

            // Mac Text
            aad.CopyTo(macData);
            ciphertext.CopyTo(macData.Slice(aadPaddedLen, ciphertextLen));

            // Mac Length
            //macData[aadPaddedLen + ciphertextPaddedLen] = (byte)aad.Length;
            //macData[aadPaddedLen + ciphertextPaddedLen + 8] = (byte)ciphertextLen;
            SetMacLength(macData, aadPaddedLen + ciphertextPaddedLen, aad.Length);
            SetMacLength(macData, aadPaddedLen + ciphertextPaddedLen + sizeof(ulong), ciphertextLen);

            return macData;
        }

        private void SetMacLength(Span<byte> macData, int offset, int value)
        {
            //var lenData = new byte[8];
            //ByteIntegerConverter.StoreUInt64LittleEndian(lenData, 0, (ulong)value);

            //Array.Copy(lenData, 0, macData, offset, lenData.Length);

            ArrayUtils.StoreUInt64LittleEndian(macData, offset, (ulong)value);
        }
    }
}
