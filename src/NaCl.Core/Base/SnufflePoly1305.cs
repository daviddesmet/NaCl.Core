namespace NaCl.Core.Base
{
    using System;
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
        //private readonly byte[] Key;
        private Snuffle _snuffle;
        private Snuffle _macKeySnuffle;
        public const string AEAD_EXCEPTION_INVALID_TAG = "AEAD Bad Tag Exception";

        /// <summary>
        /// Initializes a new instance of the <see cref="SnufflePoly1305"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        public SnufflePoly1305(in byte[] key)
        {
            //Key = key;
            _snuffle = CreateSnuffleInstance(key, 1);
            _macKeySnuffle = CreateSnuffleInstance(key, 0);
        }

        /// <summary>
        /// Creates the snuffle instance.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        /// <returns>Snuffle.</returns>
        protected abstract Snuffle CreateSnuffleInstance(in byte[] key, int initialCounter);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="aad"> and a random auto-generated nonce.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="aad">The optional associated data.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographicException">plaintext</exception>
        public virtual byte[] Encrypt(byte[] plaintext, byte[] aad = null) => Encrypt((ReadOnlySpan<byte>)plaintext, (ReadOnlySpan<byte>)aad);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="aad"> and a random auto-generated nonce.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="aad">The optional associated data.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographicException">plaintext</exception>
        public virtual byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad = default)
        {
            //if (plaintext.Length > int.MaxValue - _snuffle.NonceSizeInBytes() - Poly1305.MAC_TAG_SIZE_IN_BYTES)
            //    throw new CryptographicException($"The {nameof(plaintext)} is too long.");

            var nonce = new byte[_snuffle.NonceSizeInBytes];
            RandomNumberGenerator.Create().GetBytes(nonce);

            var ciphertext = Encrypt(plaintext, aad, nonce);

            // return nonce.Concat(ciphertext).ToArray(); // could be inefficient
            return CryptoBytes.Combine(nonce, ciphertext);
        }

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an <paramref name="aad"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="aad">The associated data.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographicException">plaintext</exception>
        public virtual byte[] Encrypt(byte[] plaintext, byte[] aad, byte[] nonce) => Encrypt((ReadOnlySpan<byte>)plaintext, (ReadOnlySpan<byte>)aad, (ReadOnlySpan<byte>)nonce);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an <paramref name="aad"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="aad">The associated data.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographicException">plaintext</exception>
        public virtual byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce)
        {
            //if (plaintext.Length > int.MaxValue - _snuffle.NonceSizeInBytes() - Poly1305.MAC_TAG_SIZE_IN_BYTES)
            //    throw new CryptographicException($"The {nameof(plaintext)} is too long.");

            if (nonce.IsEmpty || nonce.Length != _snuffle.NonceSizeInBytes)
                throw new CryptographicException(_snuffle.FormatNonceLengthExceptionMessage(GetType().Name, nonce.Length, _snuffle.NonceSizeInBytes));

            var ciphertext = _snuffle.Encrypt(plaintext, nonce);

            var tag = Poly1305.ComputeMac(GetMacKey(nonce), GetMacDataRfc8439(aad, ciphertext));

            // Array.Resize(ref ciphertext, ciphertext.Length + Poly1305.MAC_TAG_SIZE_IN_BYTES);
            // Array.Copy(tag, 0, ciphertext, ciphertext.Length - Poly1305.MAC_TAG_SIZE_IN_BYTES, tag.Length);

            // return ciphertext;
            // return ciphertext.Concat(tag).ToArray(); // could be inefficient
            return CryptoBytes.Combine(ciphertext, tag);
        }

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="aad">.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="aad">The optional associated data.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographicException"></exception>
        public virtual byte[] Decrypt(byte[] ciphertext, byte[] aad = null) => Decrypt((ReadOnlySpan<byte>)ciphertext, (ReadOnlySpan<byte>)aad);

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an optional <paramref name="aad">.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="aad">The optional associated data.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographicException"></exception>
        public virtual byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad = default)
        {
            if (ciphertext.Length < _snuffle.NonceSizeInBytes + Poly1305.MAC_TAG_SIZE_IN_BYTES)
                throw new CryptographicException($"The {nameof(ciphertext)} is too short.");

            return Decrypt(ciphertext.Slice(_snuffle.NonceSizeInBytes), aad, ciphertext.Slice(0, _snuffle.NonceSizeInBytes));
        }

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an <paramref name="aad"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="aad">The associated data.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographicException"></exception>
        public virtual byte[] Decrypt(byte[] ciphertext, byte[] aad, byte[] nonce) => Decrypt((ReadOnlySpan<byte>)ciphertext, (ReadOnlySpan<byte>)aad, (ReadOnlySpan<byte>)nonce);

        /// <summary>
        /// Decrypts the specified <paramref name="ciphertext"> and computes a MAC with <see cref="Poly1305"/> authentication based on an <paramref name="aad"> and a <paramref name="nonce">.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <param name="aad">The associated data.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographicException"></exception>
        public virtual byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> nonce)
        {
            if (ciphertext.Length + nonce.Length < _snuffle.NonceSizeInBytes + Poly1305.MAC_TAG_SIZE_IN_BYTES)
                throw new CryptographicException($"The {nameof(ciphertext)} is too short.");

            if (nonce.IsEmpty || nonce.Length != _snuffle.NonceSizeInBytes)
                throw new CryptographicException(_snuffle.FormatNonceLengthExceptionMessage(_snuffle.GetType().Name, nonce.Length, _snuffle.NonceSizeInBytes));

            var limit = ciphertext.Length - Poly1305.MAC_TAG_SIZE_IN_BYTES;

            try
            {
                Poly1305.VerifyMac(GetMacKey(nonce), GetMacDataRfc8439(aad, ciphertext.Slice(0, limit)), ciphertext.Slice(limit, Poly1305.MAC_TAG_SIZE_IN_BYTES));
            }
            catch (Exception ex)
            {
                throw new CryptographicException(AEAD_EXCEPTION_INVALID_TAG, ex);
            }

            return _snuffle.Decrypt(ciphertext.Slice(0, limit), nonce);
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
        private byte[] GetMacDataRfc8439(ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext)
        {
            var aadPaddedLen = (aad.Length % 16 == 0) ? aad.Length : (aad.Length + 16 - aad.Length % 16);
            var ciphertextLen = ciphertext.Length;
            var ciphertextPaddedLen = (ciphertextLen % 16 == 0) ? ciphertextLen : (ciphertextLen + 16 - ciphertextLen % 16);

            var macData = new byte[aadPaddedLen + ciphertextPaddedLen + 16];

            // Mac Text
            //aad.CopyTo(macData);
            Array.Copy(aad.ToArray(), macData, aad.Length);
            Array.Copy(ciphertext.ToArray(), 0, macData, aadPaddedLen, ciphertextLen);

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
