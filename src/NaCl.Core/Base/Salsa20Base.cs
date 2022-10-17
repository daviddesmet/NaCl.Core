namespace NaCl.Core.Base
{
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    using Internal;

    /// <summary>
    /// Base class for <seealso cref="NaCl.Core.Salsa20" /> and <seealso cref="NaCl.Core.XSalsa20" />.
    /// </summary>
    /// <seealso cref="NaCl.Core.Base.Snuffle" />
    public abstract class Salsa20Base : Snuffle
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Salsa20Base"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        protected Salsa20Base(ReadOnlyMemory<byte> key, int initialCounter) : base(key, initialCounter) { }

        /// <inheritdoc />
        public override int BlockSizeInBytes => BLOCK_SIZE_IN_BYTES;

        /// <summary>
        /// Sets the initial <paramref name="state"/> from <paramref name="nonce"/> and <paramref name="counter"/>.
        /// Salsa20 has a different logic than XSalsa20, because the former uses a 8-byte nonce, but the later uses 24-byte.
        /// </summary>
        /// <param name="state">The state.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="counter">The counter.</param>
        protected abstract void SetInitialState(Span<uint> state, ReadOnlySpan<byte> nonce, int counter);

        /// <inheritdoc />
        public override void ProcessKeyStreamBlock(ReadOnlySpan<byte> nonce, int counter, Span<byte> block)
        {
            if (block.Length != BLOCK_SIZE_IN_BYTES)
                throw new CryptographicException($"The key stream block length is not valid. The length in bytes must be {BLOCK_SIZE_IN_BYTES}.");

            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
            SetInitialState(state, nonce, counter);

#if INTRINSICS
            if (System.Runtime.Intrinsics.X86.Sse3.IsSupported && BitConverter.IsLittleEndian)
            {
                Salsa20BaseIntrinsics.Salsa20KeyStream(state, block);
                return;
            }
#endif

            // Create a copy of the state and then run 20 rounds on it,
            // alternating between "column rounds" and "diagonal rounds"; each round consisting of four quarter-rounds.
            Span<uint> workingState = stackalloc uint[BLOCK_SIZE_IN_INTS];
            state.CopyTo(workingState);
            ShuffleState(workingState);

            // At the end of the rounds, add the result to the original state.
            for (var i = 0; i < BLOCK_SIZE_IN_INTS; i++)
                state[i] += workingState[i];

            ArrayUtils.StoreArray16UInt32LittleEndian(block, 0, state);
        }

#if INTRINSICS
        public override unsafe void ProcessStream(ReadOnlySpan<byte> nonce, Span<byte> output, ReadOnlySpan<byte> input, int initialCounter, int offset = 0)
        {
            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
            SetInitialState(state, nonce, initialCounter);
            var c = output.Slice(offset);

            Salsa20BaseIntrinsics.Salsa20(state, input, c, (ulong)input.Length);
        }
#endif

        /// <summary>
        /// Process a pseudorandom key stream block, converting the key and part of the <paramref name="nonce"/> into a <paramref name="subKey"/>, and the remainder of the <paramref name="nonce"/>.
        /// </summary>
        /// <param name="subKey">The subKey.</param>
        /// <param name="nonce">The nonce.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void HSalsa20(Span<byte> subKey, ReadOnlySpan<byte> nonce)
        {
            // See: http://cr.yp.to/snuffle/xsalsa-20081128.pdf under 2. Specification - Definition of HSalsa20

            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];

            // Setting HSalsa20 initial state
            HSalsa20InitialState(state, nonce);
            
#if INTRINSICS
            if (System.Runtime.Intrinsics.X86.Sse2.IsSupported && BitConverter.IsLittleEndian)
            {
                Salsa20BaseIntrinsics.HSalsa20(state, subKey);
                return;
            }
#endif

            // Block function
            ShuffleState(state);

            state[1] = state[5];
            state[2] = state[10];
            state[3] = state[15];
            state[4] = state[6];
            state[5] = state[7];
            state[6] = state[8];
            state[7] = state[9];

            ArrayUtils.StoreArray8UInt32LittleEndian(subKey, 0, state);
        }

        /// <summary>
        /// Sets the initial <paramref name="state"/> of the HSalsa20 using the key and the <paramref name="nonce"/>.
        /// </summary>
        /// <param name="state">The state.</param>
        /// <param name="nonce">The nonce.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void HSalsa20InitialState(Span<uint> state, ReadOnlySpan<byte> nonce)
        {
            // The internal state is made of sixteen 32-bit words arranged as a 4×4 matrix.
            //  0  1  2  3
            //  4  5  6  7
            //  8  9 10 11
            // 12 13 14 15

            // Set Salsa20 constant
            // The first four words in diagonal (0,5,10,15) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
            SetSigma(state);

            // Set 256-bit Key
            // The next eight words (1,2,3,4,11,12,13,14) are taken from the 256-bit key in little-endian order, in 4-byte chunks.
            SetKey(state, Key.Span);

            // Set 128-bit Nonce
            state[6] = ArrayUtils.LoadUInt32LittleEndian(nonce, 0);
            state[7] = ArrayUtils.LoadUInt32LittleEndian(nonce, 4);
            state[8] = ArrayUtils.LoadUInt32LittleEndian(nonce, 8);
            state[9] = ArrayUtils.LoadUInt32LittleEndian(nonce, 12);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        protected static void ShuffleState(Span<uint> state)
        {
            // 10 loops × 2 rounds/loop = 20 rounds
            for (var i = 0; i < 10; i++)
            {
                // Odd round
                QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);    // column 1
                QuarterRound(ref state[5], ref state[9], ref state[13], ref state[1]);    // column 2
                QuarterRound(ref state[10], ref state[14], ref state[2], ref state[6]);   // column 3
                QuarterRound(ref state[15], ref state[3], ref state[7], ref state[11]);   // column 4

                // Even round
                QuarterRound(ref state[0], ref state[1], ref state[2], ref state[3]);     // row 1
                QuarterRound(ref state[5], ref state[6], ref state[7], ref state[4]);     // row 2
                QuarterRound(ref state[10], ref state[11], ref state[8], ref state[9]);   // row 3
                QuarterRound(ref state[15], ref state[12], ref state[13], ref state[14]); // row 4
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            b ^= BitUtils.RotateLeft(a + d, 7);
            c ^= BitUtils.RotateLeft(b + a, 9);
            d ^= BitUtils.RotateLeft(c + b, 13);
            a ^= BitUtils.RotateLeft(d + c, 18);
        }

        /// <summary>
        /// Sets the Salsa20 constant.
        /// </summary>
        /// <param name="state">The state.</param>
        protected static void SetSigma(Span<uint> state)
        {
            state[0] = SIGMA[0];
            state[5] = SIGMA[1];
            state[10] = SIGMA[2];
            state[15] = SIGMA[3];
        }

        /// <summary>
        /// Sets the 256-bit Key.
        /// </summary>
        /// <param name="state">The state.</param>
        /// <param name="key">The key.</param>
        protected static void SetKey(Span<uint> state, ReadOnlySpan<byte> key)
        {
            state[1] = ArrayUtils.LoadUInt32LittleEndian(key, 0);
            state[2] = ArrayUtils.LoadUInt32LittleEndian(key, 4);
            state[3] = ArrayUtils.LoadUInt32LittleEndian(key, 8);
            state[4] = ArrayUtils.LoadUInt32LittleEndian(key, 12);
            state[11] = ArrayUtils.LoadUInt32LittleEndian(key, 16);
            state[12] = ArrayUtils.LoadUInt32LittleEndian(key, 20);
            state[13] = ArrayUtils.LoadUInt32LittleEndian(key, 24);
            state[14] = ArrayUtils.LoadUInt32LittleEndian(key, 28);
        }
    }
}