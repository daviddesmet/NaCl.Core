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
        public static int BLOCK_SIZE_IN_INTS = 16;
        public static int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4;
        public static int KEY_SIZE_IN_INTS = 8;
        public static int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4;

        public static uint[] SIGMA = new uint[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 }; //Encoding.ASCII.GetBytes("expand 32-byte k");

        protected readonly byte[] Key;
        protected readonly int InitialCounter;

        /// <summary>
        /// Initializes a new instance of the <see cref="Snuffle"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        /// <exception cref="CryptographyException"></exception>
        public Snuffle(in byte[] key, int initialCounter)
        {
            if (key.Length != KEY_SIZE_IN_BYTES)
                throw new CryptographyException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

            Key = key;
            InitialCounter = initialCounter;
        }

        /// <summary>
        /// Process the key stream block <paramref name="block"> from <paramref name="nonce"> and <paramref name="counter">.
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
        public abstract int NonceSizeInBytes();

        /// <summary>
        /// Encrypts the specified plaintext.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="nonce">The optional nonce.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographyException">plaintext or ciphertext</exception>
        public virtual byte[] Encrypt(byte[] plaintext, byte[] nonce = null) => Encrypt(plaintext.AsSpan(), nonce);

        /// <summary>
        /// Encrypts the specified plaintext.
        /// </summary>
        /// <param name="plaintext">The plaintext.</param>
        /// <param name="nonce">The optional nonce.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographyException">plaintext or ciphertext</exception>
        public virtual byte[] Encrypt(ReadOnlySpan<byte> plaintext, byte[] nonce = null)
        {
            if (plaintext.Length > int.MaxValue - NonceSizeInBytes())
                throw new CryptographyException($"The {nameof(plaintext)} is too long.");

            if (nonce != null && nonce.Length != NonceSizeInBytes())
                throw new CryptographyException($"The nonce length in bytes must be {NonceSizeInBytes()}.");

            if (nonce is null)
            {
                nonce = new byte[NonceSizeInBytes()];
                RandomNumberGenerator.Create().GetBytes(nonce);
            }

            var ciphertext = new byte[plaintext.Length + NonceSizeInBytes()];

            Array.Copy(nonce, ciphertext, nonce.Length);
            Process(nonce.AsSpan(), ciphertext, plaintext, nonce.Length);

            return ciphertext;
        }

        /// <summary>
        /// Decrypts the specified ciphertext.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographyException">ciphertext</exception>
        public virtual byte[] Decrypt(byte[] ciphertext) => Decrypt(ciphertext.AsSpan());

        /// <summary>
        /// Decrypts the specified ciphertext.
        /// </summary>
        /// <param name="ciphertext">The ciphertext.</param>
        /// <returns>System.Byte[].</returns>
        /// <exception cref="CryptographyException">ciphertext</exception>
        public virtual byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
        {
            if (ciphertext.Length < NonceSizeInBytes())
                throw new CryptographyException($"The {nameof(ciphertext)} is too short.");

            var plaintext = new byte[ciphertext.Length - NonceSizeInBytes()];

            Process(ciphertext.Slice(0, NonceSizeInBytes()), plaintext, ciphertext.Slice(NonceSizeInBytes()));

            return plaintext;
        }

        /// <summary>
        /// Processes the Encryption/Decryption function.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <param name="output">The output.</param>
        /// <param name="input">The input.</param>
        /// <param name="offset">The output's starting offset.</param>
        private void Process(ReadOnlySpan<byte> nonce, byte[] output, ReadOnlySpan<byte> input, int offset = 0)
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

        protected static uint RotateLeft(uint x, int y) => (x << y) | (x >> (32 - y));

        /// <summary>
        /// XOR the specified output.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <param name="input">The input.</param>
        /// <param name="block">The key stream block.</param>
        /// <param name="len">The length.</param>
        /// <param name="offset">The output's starting offset.</param>
        /// <param name="curBlock">The current block number.</param>
        /// <exception cref="CryptographyException">The combination of blocks, offsets and length to be XORed is out-of-bonds.</exception>
        private static void Xor(byte[] output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> block, int len, int offset, int curBlock)
        {
            var blockOffset = curBlock * BLOCK_SIZE_IN_BYTES;

            if (len < 0 || offset < 0 || curBlock < 0 || output.Length < len || (input.Length - blockOffset) < len || block.Length < len)
                throw new CryptographyException("The combination of blocks, offsets and length to be XORed is out-of-bonds.");

            for (var i = 0; i < len; i++)
                output[i + offset + blockOffset] = (byte)(input[i + blockOffset] ^ block[i]);
        }
    }
}
