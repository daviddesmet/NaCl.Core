namespace NaCl.Core.Base
{
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    using Internal;

    internal class ChaCha20Core : IChaCha20Core
    {
        public const int BLOCK_SIZE_IN_BYTES = Snuffle.BLOCK_SIZE_IN_BYTES;
        public const int BLOCK_SIZE_IN_INTS = Snuffle.BLOCK_SIZE_IN_INTS;
        
        private readonly ChaCha20Base _chaCha20;
        public ChaCha20Core(ChaCha20Base chaCha20) => _chaCha20 = chaCha20;

        public void ProcessKeyStreamBlock(ReadOnlySpan<byte> nonce, int counter, Span<byte> block)
        {
            if (block.Length != BLOCK_SIZE_IN_BYTES)
                throw new CryptographicException($"The key stream block length is not valid. The length in bytes must be {BLOCK_SIZE_IN_BYTES}.");

            // Set the initial state based on https://tools.ietf.org/html/rfc8439#section-2.3
            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
            _chaCha20.SetInitialState(state, nonce, counter);

            // Create a copy of the state and then run 20 rounds on it,
            // alternating between "column rounds" and "diagonal rounds"; each round consisting of four quarter-rounds.
            Span<uint> workingState = stackalloc uint[BLOCK_SIZE_IN_INTS];
            state.CopyTo(workingState);
            ChaCha20Base.ShuffleState(state);

            // At the end of the rounds, add the result to the original state.
            for (var i = 0; i < BLOCK_SIZE_IN_INTS; i++)
                state[i] += workingState[i];

            ArrayUtils.StoreArray16UInt32LittleEndian(block, 0, state);
        }

        public void Process(ReadOnlySpan<byte> nonce, Span<byte> output, ReadOnlySpan<byte> input, int offset = 0) => _chaCha20.Process(nonce, output, input, offset);

        /// <summary>
        /// Process a pseudorandom key stream block, converting the key and part of the <paramref name="nonce"/> into a <paramref name="subKey"/>, and the remainder of the <paramref name="nonce"/>.
        /// </summary>
        /// <param name="subKey">The subKey.</param>
        /// <param name="nonce">The nonce.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void HChaCha20(Span<byte> subKey, ReadOnlySpan<byte> nonce)
        {
            // See https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.
            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];

            // Setting HChaCha20 initial state
            _chaCha20.HChaCha20InitialState(state, nonce);

            // Block function
            ChaCha20Base.ShuffleState(state);

            state[4] = state[12];
            state[5] = state[13];
            state[6] = state[14];
            state[7] = state[15];

            ArrayUtils.StoreArray8UInt32LittleEndian(subKey, 0, state);
        }
    }
}
