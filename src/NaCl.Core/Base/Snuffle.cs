namespace NaCl.Core.Base
{
    using System;
    using System.Buffers;
    using System.Security.Cryptography;

#if INTRINSICS
    using System.Runtime.Intrinsics.X86;
#endif


    /// <summary>
    /// Abstract base class for XSalsa20, ChaCha20, XChaCha20 and their variants.
    /// </summary>
    /// <remarks>
    /// Variants of Snuffle have two differences: the size of the nonce and the block function that
    /// produces a key stream block from a key, a nonce, and a counter. Subclasses of this class
    /// specifying these two information by overriding <seealso cref="NaCl.Core.Base.Snuffle.NonceSizeInBytes" /> and <seealso cref="NaCl.Core.Base.Snuffle.BlockSizeInBytes" /> and <seealso cref="NaCl.Core.Base.Snuffle.ProcessKeyStreamBlock(ReadOnlySpan{byte},int,Span{byte})" />.
    ///
    /// Concrete implementations of this class are meant to be used to construct an AEAD with <seealso cref="NaCl.Core.Poly1305" />. The
    /// base class of these AEAD constructions is <seealso cref="NaCl.Core.Base.SnufflePoly1305" />.
    /// For example, <seealso cref="NaCl.Core.XChaCha20" /> is a subclass of this class and a
    /// concrete Snuffle implementation, and <seealso cref="NaCl.Core.XChaCha20Poly1305" /> is
    /// a subclass of <seealso cref="NaCl.Core.Base.SnufflePoly1305" /> and a concrete AEAD construction.
    /// </remarks>
    public abstract class Snuffle
    {
        protected const int KEY_SIZE_IN_INTS = 8;
        public const int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
        protected const int BLOCK_SIZE_IN_INTS = 16;
        public const int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4; // 64

        protected static uint[] SIGMA = new uint[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 }; // "expand 32-byte k" (4 words constant: "expa", "nd 3", "2-by", and "te k")

        protected readonly ReadOnlyMemory<byte> Key;
        protected readonly int InitialCounter;

        /// <summary>
        /// Initializes a new instance of the <see cref="Snuffle"/> class.
        /// </summary>
        /// <param name="key">The secret key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        /// <exception cref="CryptographicException"></exception>
        protected Snuffle(ReadOnlyMemory<byte> key, int initialCounter)
        {
            if (key.Length != KEY_SIZE_IN_BYTES)
                throw new CryptographicException($"The key length in bytes must be {KEY_SIZE_IN_BYTES}.");

            Key = key;
            InitialCounter = initialCounter;
        }

        /// <summary>
        /// Process the key stream block <paramref name="block"/> from <paramref name="nonce"/> and <paramref name="counter"/>.
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

#if INTRINSICS
        public abstract void ProcessStream(ReadOnlySpan<byte> nonce, Span<byte> output, ReadOnlySpan<byte> input, int initialCounter, int offset = 0);
#endif

        /// <summary>
        /// The size of the nonce in bytes.
        /// Salsa20 uses a 8-byte (64-bit) nonce, ChaCha20 uses a 12-byte (96-bit) nonce, but XSalsa20 and XChaCha20 use a 24-byte (192-bit) nonce.
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
        /// <exception cref="CryptographicException">plaintext or nonce</exception>
        public void Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, Span<byte> ciphertext)
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
        /// Decrypts the <paramref name="ciphertext"/> into the <paramref name="plaintext"/> provided destination buffer using the associated <paramref name="nonce"/>.
        /// </summary>
        /// <param name="ciphertext">The encrypted content to decrypt.</param>
        /// <param name="nonce">The nonce associated with this message, which must match the value provided during encryption.</param>
        /// <param name="plaintext">The byte span to receive the decrypted contents.</param>
        /// <exception cref="CryptographicException">ciphertext or nonce.</exception>
        public void Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, Span<byte> plaintext)
        {
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
#if INTRINSICS
            if (Sse3.IsSupported)
            {
                ProcessStream(nonce, output, input, InitialCounter, offset);
                return;
            }
#endif

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
        /// XOR the specified output.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <param name="input">The input.</param>
        /// <param name="block">The key stream block.</param>
        /// <param name="len">The length.</param>
        /// <param name="offset">The output's starting offset.</param>
        /// <param name="curBlock">The current block number.</param>
        /// <exception cref="CryptographicException">The combination of blocks, offsets and length to be XORed is out-of-bonds.</exception>
        private void Xor(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> block, int len, int offset, int curBlock)
        {
            var blockOffset = curBlock * BlockSizeInBytes;

            // Since is not called directly from outside, there's no need to check
            //if (len < 0 || offset < 0 || curBlock < 0 || output.Length < len || (input.Length - blockOffset) < len || block.Length < len)
            //    throw new CryptographicException("The combination of blocks, offsets and length to be XORed is out-of-bonds.");

            for (var i = 0; i < len; i++)
                output[i + offset + blockOffset] = (byte)(input[i + blockOffset] ^ block[i]);
        }
    }
}
