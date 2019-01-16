namespace NaCl.Core.Base
{
    using System;
    using System.Security.Cryptography;

    using Internal;

    /// <summary>
    /// Base class for <seealso cref="NaCl.Core.ChaCha20" /> and <seealso cref="NaCl.Core.XChaCha20" />.
    /// </summary>
    /// <seealso cref="NaCl.Core.Internal.Snuffle" />
    public abstract class ChaCha20Base : Snuffle
    {
        private readonly byte[] ZERO_16_BYTES = new byte[16];

        /// <summary>
        /// Initializes a new instance of the <see cref="ChaCha20Base"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        public ChaCha20Base(in byte[] key, int initialCounter) : base(key, initialCounter) { }

        /// <summary>
        /// Returns the initial state from <paramref name="nonce"/> and <paramref name="counter">.
        /// ChaCha20 has a different logic than XChaCha20, because the former uses a 12-byte nonce, but the later uses 24-byte.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <param name="counter">The counter.</param>
        /// <returns>Array16&lt;System.UInt32&gt;.</returns>
        protected abstract Array16<uint> CreateInitialState(ReadOnlySpan<byte> nonce, int counter);

        /// <inheritdoc />
        public override void ProcessKeyStreamBlock(ReadOnlySpan<byte> nonce, int counter, Span<byte> block)
        {
            if (block.Length != BLOCK_SIZE_IN_BYTES)
                throw new CryptographicException($"The keystream block length is not valid. The length in bytes must be {BLOCK_SIZE_IN_BYTES}.");

            // Creates the initial state.
            // https://tools.ietf.org/html/rfc8439#section-2.3.
            var state = CreateInitialState(nonce, counter);

            // Create a copy of the state and then
            // run 20 rounds on it, alternating between "column rounds" and "diagonal rounds"; each round consisting of four quarter-rounds.
            var workingState = ByteIntegerConverter.Array16ToArray(state);
            ShuffleState(ref workingState);

            // At the end of the rounds, add the result to the original state.
            unchecked
            {
                state.x0 += workingState[0];
                state.x1 += workingState[1];
                state.x2 += workingState[2];
                state.x3 += workingState[3];
                state.x4 += workingState[4];
                state.x5 += workingState[5];
                state.x6 += workingState[6];
                state.x7 += workingState[7];
                state.x8 += workingState[8];
                state.x9 += workingState[9];
                state.x10 += workingState[10];
                state.x11 += workingState[11];
                state.x12 += workingState[12];
                state.x13 += workingState[13];
                state.x14 += workingState[14];
                state.x15 += workingState[15];
            }

            ByteIntegerConverter.WriteLittleEndian32(block, 0, ref state);
        }

        /// <summary>
        /// Process a pseudorandom keystream block, converting the key and part of the nonce into a subkey, and the remainder of the nonce.
        /// </summary>
        /// <returns>System.Byte[].</returns>
        public byte[] HChaCha20() => HChaCha20(ZERO_16_BYTES);

        /// <summary>
        /// Process a pseudorandom keystream block, converting the key and part of the <paramref name="nonce"> into a subkey, and the remainder of the nonce.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <returns>System.Byte[].</returns>
        public byte[] HChaCha20(ReadOnlySpan<byte> nonce)
        {
            // See https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.

            var state = new Array16<uint>();

            // Set ChaCha20 constant
            SetSigma(ref state);
            
            // Set 256-bit Key
            SetKey(ref state, Key);

            // Set 128-bit Nonce
            state.x12 = ByteIntegerConverter.LoadLittleEndian32(nonce, 0);
            state.x13 = ByteIntegerConverter.LoadLittleEndian32(nonce, 4);
            state.x14 = ByteIntegerConverter.LoadLittleEndian32(nonce, 8);
            state.x15 = ByteIntegerConverter.LoadLittleEndian32(nonce, 12);

            // Block function
            ShuffleState(ref state);

            state.x4 = state.x12;
            state.x5 = state.x13;
            state.x6 = state.x14;
            state.x7 = state.x15;

            var output = new byte[KEY_SIZE_IN_BYTES]; // TODO: Remove allocation
            ByteIntegerConverter.Array8StoreLittleEndian32(output, 0, ref state);
            return output;
        }

        protected static void ShuffleState(ref Array16<uint> state)
        {
            var x0 = state.x0;
            var x1 = state.x1;
            var x2 = state.x2;
            var x3 = state.x3;
            var x4 = state.x4;
            var x5 = state.x5;
            var x6 = state.x6;
            var x7 = state.x7;
            var x8 = state.x8;
            var x9 = state.x9;
            var x10 = state.x10;
            var x11 = state.x11;
            var x12 = state.x12;
            var x13 = state.x13;
            var x14 = state.x14;
            var x15 = state.x15;

            unchecked
            {
                // 10 * 8 quarter rounds = 20 rounds
                for (var i = 0; i < 10; ++i)
                {
                    // Column quarter rounds
                    x0 += x4;
                    x12 = RotateLeft(x12 ^ x0, 16);
                    x8 += x12;
                    x4 = RotateLeft(x4 ^ x8, 12);
                    x0 += x4;
                    x12 = RotateLeft(x12 ^ x0, 8);
                    x8 += x12;
                    x4 = RotateLeft(x4 ^ x8, 7);

                    x1 += x5;
                    x13 = RotateLeft(x13 ^ x1, 16);
                    x9 += x13;
                    x5 = RotateLeft(x5 ^ x9, 12);
                    x1 += x5;
                    x13 = RotateLeft(x13 ^ x1, 8);
                    x9 += x13;
                    x5 = RotateLeft(x5 ^ x9, 7);

                    x2 += x6;
                    x14 = RotateLeft(x14 ^ x2, 16);
                    x10 += x14;
                    x6 = RotateLeft(x6 ^ x10, 12);
                    x2 += x6;
                    x14 = RotateLeft(x14 ^ x2, 8);
                    x10 += x14;
                    x6 = RotateLeft(x6 ^ x10, 7);

                    x3 += x7;
                    x15 = RotateLeft(x15 ^ x3, 16);
                    x11 += x15;
                    x7 = RotateLeft(x7 ^ x11, 12);
                    x3 += x7;
                    x15 = RotateLeft(x15 ^ x3, 8);
                    x11 += x15;
                    x7 = RotateLeft(x7 ^ x11, 7);

                    // Diagonal quarter rounds
                    x0 += x5;
                    x15 = RotateLeft(x15 ^ x0, 16);
                    x10 += x15;
                    x5 = RotateLeft(x5 ^ x10, 12);
                    x0 += x5;
                    x15 = RotateLeft(x15 ^ x0, 8);
                    x10 += x15;
                    x5 = RotateLeft(x5 ^ x10, 7);

                    x1 += x6;
                    x12 = RotateLeft(x12 ^ x1, 16);
                    x11 += x12;
                    x6 = RotateLeft(x6 ^ x11, 12);
                    x1 += x6;
                    x12 = RotateLeft(x12 ^ x1, 8);
                    x11 += x12;
                    x6 = RotateLeft(x6 ^ x11, 7);

                    x2 += x7;
                    x13 = RotateLeft(x13 ^ x2, 16);
                    x8 += x13;
                    x7 = RotateLeft(x7 ^ x8, 12);
                    x2 += x7;
                    x13 = RotateLeft(x13 ^ x2, 8);
                    x8 += x13;
                    x7 = RotateLeft(x7 ^ x8, 7);

                    x3 += x4;
                    x14 = RotateLeft(x14 ^ x3, 16);
                    x9 += x14;
                    x4 = RotateLeft(x4 ^ x9, 12);
                    x3 += x4;
                    x14 = RotateLeft(x14 ^ x3, 8);
                    x9 += x14;
                    x4 = RotateLeft(x4 ^ x9, 7);
                }
            }

            state.x0 = x0;
            state.x1 = x1;
            state.x2 = x2;
            state.x3 = x3;
            state.x4 = x4;
            state.x5 = x5;
            state.x6 = x6;
            state.x7 = x7;
            state.x8 = x8;
            state.x9 = x9;
            state.x10 = x10;
            state.x11 = x11;
            state.x12 = x12;
            state.x13 = x13;
            state.x14 = x14;
            state.x15 = x15;
        }

        protected static void ShuffleState(ref uint[] state)
        {
            for (var i = 0; i < 10; i++)
            {
                QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);
                QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);
                QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]);
                QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]);
                QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]);
                QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]);
                QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);
                QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);
            }
        }

        public static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b;
            d = RotateLeft(d ^ a, 16);
            c += d;
            b = RotateLeft(b ^ c, 12);
            a += b;
            d = RotateLeft(d ^ a, 8);
            c += d;
            b = RotateLeft(b ^ c, 7);
        }

        protected static void SetSigma(ref Array16<uint> state)
        {
            state.x0 = SIGMA[0];
            state.x1 = SIGMA[1];
            state.x2 = SIGMA[2];
            state.x3 = SIGMA[3];
        }

        protected static void SetKey(ref Array16<uint> state, ReadOnlySpan<byte> key)
        {
            state.x4 = ByteIntegerConverter.LoadLittleEndian32(key, 0);
            state.x5 = ByteIntegerConverter.LoadLittleEndian32(key, 4);
            state.x6 = ByteIntegerConverter.LoadLittleEndian32(key, 8);
            state.x7 = ByteIntegerConverter.LoadLittleEndian32(key, 12);
            state.x8 = ByteIntegerConverter.LoadLittleEndian32(key, 16);
            state.x9 = ByteIntegerConverter.LoadLittleEndian32(key, 20);
            state.x10 = ByteIntegerConverter.LoadLittleEndian32(key, 24);
            state.x11 = ByteIntegerConverter.LoadLittleEndian32(key, 28);
        }
    }
}
