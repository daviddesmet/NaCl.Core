namespace NaCl.Core.Base
{
    using System;
    using System.Buffers;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// Abstract base class for XSalsa20, ChaCha20, XChaCha20 and their variants.
    /// </summary>
    /// <remarks>
    /// Variants of Snuffle have two differences: the size of the nonce and the block function that
    /// produces a key stream block from a key, a nonce, and a counter. Subclasses of this class
    /// specifying these two information by overriding <seealso cref="NaCl.Core.Base.Snuffle.NonceSizeInBytes()" /> and <seealso cref="NaCl.Core.Base.Snuffle.GetKeyStreamBlock(byte[], int)" />.
    ///
    /// Concrete implementations of this class are meant to be used to construct an Aead with <seealso cref="NaCl.Core.Poly1305" />. The
    /// base class of these Aead constructions is <seealso cref="NaCl.Core.Base.SnufflePoly1305" />.
    /// For example, <seealso cref="NaCl.Core.XChaCha20" /> is a subclass of this class and a
    /// concrete Snuffle implementation, and <seealso cref="NaCl.Core.XChaCha20Poly1305" /> is
    /// a subclass of <seealso cref="NaCl.Core.Base.SnufflePoly1305" /> and a concrete Aead construction.
    /// </remarks>
    public abstract class Snuffle
    {
        public const int BLOCK_SIZE_IN_INTS = 16;
        public static int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4; // 64
        public const int KEY_SIZE_IN_INTS = 8;
        public static int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32

        public static uint[] SIGMA = new uint[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 }; //Encoding.ASCII.GetBytes("expand 32-byte k");

        protected readonly ReadOnlyMemory<byte> Key;
        protected readonly int InitialCounter;

        /// <summary>
        /// Initializes a new instance of the <see cref="Snuffle"/> class.
        /// </summary>
        /// <param name="key">The secret key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        /// <exception cref="CryptographicException"></exception>
        public Snuffle(ReadOnlyMemory<byte> key, int initialCounter)
        {
            if (key.Length != KEY_SIZE_IN_BYTES)
                throw new CryptographicException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

            Key = key;
            InitialCounter = initialCounter;
        }

        /// <summary>
        /// Process the keystream block <paramref name="block"> from <paramref name="nonce"> and <paramref name="counter">.
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
        /// The size of the randomly generated nonces.
        /// ChaCha20 uses 12-byte nonces, but XSalsa20 and XChaCha20 use 24-byte nonces.
        /// </summary>
        /// <returns>System.Int32.</returns>
        public abstract int NonceSizeInBytes { get; }

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> using an unique generated nonce.
        /// </summary>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <returns>The encrypted contents.</returns>
        /// <exception cref="CryptographicException">plaintext or ciphertext</exception>
        public virtual byte[] Encrypt(byte[] plaintext) => Encrypt((ReadOnlySpan<byte>)plaintext);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> using an unique generated nonce.
        /// </summary>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <returns>The encrypted contents.</returns>
        /// <exception cref="CryptographicException">plaintext or ciphertext</exception>
        public virtual byte[] Encrypt(ReadOnlySpan<byte> plaintext)
        {
            //if (plaintext.Length > int.MaxValue - NonceSizeInBytes())
            //    throw new ArgumentException($"The {nameof(plaintext)} is too long.");

            var ciphertext = new byte[plaintext.Length + NonceSizeInBytes];

#if NETCOREAPP3_1
            Span<byte> nonce = stackalloc byte[NonceSizeInBytes];
            RandomNumberGenerator.Fill(nonce);

            nonce.CopyTo(ciphertext);
#else
            var nonce = new byte[NonceSizeInBytes];
            RandomNumberGenerator.Create().GetBytes(nonce);

            Array.Copy(nonce, ciphertext, nonce.Length);
#endif

            Process(nonce, ciphertext, plaintext, nonce.Length);

            return ciphertext;
        }

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> using the associated <paramref name="nonce">.
        /// </summary>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <returns>The encrypted contents.</returns>
        /// <exception cref="CryptographicException">plaintext or nonce</exception>
        public virtual byte[] Encrypt(byte[] plaintext, byte[] nonce) => Encrypt((ReadOnlySpan<byte>)plaintext, (ReadOnlySpan<byte>)nonce);

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> using the associated <paramref name="nonce">.
        /// </summary>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <returns>The encrypted contents.</returns>
        /// <exception cref="CryptographicException">plaintext or nonce</exception>
        public virtual byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce)
        {
            var ciphertext = new byte[plaintext.Length];
            Encrypt(plaintext, nonce, ciphertext);
            return ciphertext;
        }

        /// <summary>
        /// Encrypts the <paramref name="plaintext"> into the <paramref name="ciphertext"> destination buffer using the associated <paramref name="nonce">.
        /// </summary>
        /// <param name="plaintext">The content to encrypt.</param>
        /// <param name="nonce">The nonce associated with this message, which should be a unique value for every operation with the same key.</param>
        /// <param name="ciphertext">The byte array to receive the encrypted contents.</param>
        /// <exception cref="CryptographicException">plaintext or nonce</exception>
        public virtual void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
        {
            //if (plaintext.Length > int.MaxValue - NonceSizeInBytes())
            //    throw new ArgumentException($"The {nameof(plaintext)} is too long.");

            if (plaintext.Length != ciphertext.Length)
                throw new ArgumentException("The plaintext parameter and the ciphertext do not have the same length.");

            if (nonce.IsEmpty || nonce.Length != NonceSizeInBytes)
                throw new ArgumentException(FormatNonceLengthExceptionMessage(GetType().Name, nonce.Length, NonceSizeInBytes));

            Process(nonce, ciphertext, plaintext);
        }

        /// <summary>
        /// Decrypts the specified ciphertext.
        /// </summary>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <returns>The decrypted contents.</returns>
        /// <exception cref="CryptographicException">ciphertext</exception>
        public virtual byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
        {
            if (ciphertext.Length < NonceSizeInBytes)
                throw new ArgumentException($"The {nameof(ciphertext)} is too short.");

            var plaintext = new byte[ciphertext.Length - NonceSizeInBytes];
            Decrypt(ciphertext.Slice(NonceSizeInBytes), ciphertext.Slice(0, NonceSizeInBytes), plaintext); //Process(ciphertext.Slice(0, NonceSizeInBytes), plaintext, ciphertext.Slice(NonceSizeInBytes));
            return plaintext;
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"> using the associated <paramref name="nonce">.
        /// </summary>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <returns>The decrypted contents.</returns>
        /// <exception cref="CryptographicException">ciphertext or nonce</exception>
        public virtual byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce)
        {
            var plaintext = new byte[ciphertext.Length];
            Decrypt(ciphertext, nonce, plaintext);
            return plaintext;
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"> into the <paramref name="plaintext"> provided destination buffer using the associated <paramref name="nonce">.
        /// </summary>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="plaintext">The byte span to receive the decrypted contents.</param>
        /// <exception cref="CryptographicException">ciphertext or nonce.</exception>
        public virtual void Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext)
        {
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
            var numBlocks = (length / BLOCK_SIZE_IN_BYTES) + 1;

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

            using (var owner = MemoryPool<byte>.Shared.Rent(BLOCK_SIZE_IN_BYTES))
            {
                for (var i = 0; i < numBlocks; i++)
                {
                    ProcessKeyStreamBlock(nonce, i + InitialCounter, owner.Memory.Span);

                    if (i == numBlocks - 1)
                        Xor(output, input, owner.Memory.Span, length % BLOCK_SIZE_IN_BYTES, offset, i); // last block
                    else
                        Xor(output, input, owner.Memory.Span, BLOCK_SIZE_IN_BYTES, offset, i);

                    owner.Memory.Span.Clear();
                }
            }
        }

        /// <summary>
        /// Formats the nonce length exception message.
        /// </summary>
        /// <param name="name">The crypto primitive name.</param>
        /// <param name="actual">The actual nonce length.</param>
        /// <param name="expected">The expected nonce length.</param>
        /// <returns>System.String.</returns>
        internal string FormatNonceLengthExceptionMessage(string name, int actual, int expected) => $"{name} uses {expected * 8}-bit nonces, but got a {actual * 8}-bit nonce. The nonce length in bytes must be {expected}.";

        /// <summary>
        /// XOR the specified output.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <param name="input">The input.</param>
        /// <param name="block">The key stream block.</param>
        /// <param name="len">The length.</param>
        /// <param name="offset">The output's starting offset.</param>
        /// <param name="curBlock">The current block number.</param>
        /// <exception cref="CryptographicException">The combination of blocks, offsets and length to be XORed is out-of-bonds.</exception>
        private static void Xor(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> block, int len, int offset, int curBlock)
        {
            var blockOffset = curBlock * BLOCK_SIZE_IN_BYTES;

            // Since is not called directly from outside, there's no need to check
            //if (len < 0 || offset < 0 || curBlock < 0 || output.Length < len || (input.Length - blockOffset) < len || block.Length < len)
            //    throw new CryptographicException("The combination of blocks, offsets and length to be XORed is out-of-bonds.");

            for (var i = 0; i < len; i++)
                output[i + offset + blockOffset] = (byte)(input[i + blockOffset] ^ block[i]);
        }
    }
}
