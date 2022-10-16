namespace NaCl.Core.Base
{
    using System;
    using System.Buffers;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    using Internal;

    internal class Salsa20Core : ISalsa20Core
    {
        protected const int KEY_SIZE_IN_INTS = 8;
        public const int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
        protected const int BLOCK_SIZE_IN_INTS = 16;
        public const int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4; // 64

        protected static uint[] SIGMA = new uint[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 }; // "expand 32-byte k" (4 words constant: "expa", "nd 3", "2-by", and "te k")

        private readonly Salsa20Base _salsa20;

        public Salsa20Core(Salsa20Base salsa20) => _salsa20 = salsa20;

        public void ProcessKeyStreamBlock(ReadOnlySpan<byte> nonce, int counter, Span<byte> block)
        {
            if (block.Length != BLOCK_SIZE_IN_BYTES)
                throw new CryptographicException($"The key stream block length is not valid. The length in bytes must be {BLOCK_SIZE_IN_BYTES}.");

            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
            _salsa20.SetInitialState(state, nonce, counter);

            // Create a copy of the state and then run 20 rounds on it,
            // alternating between "column rounds" and "diagonal rounds"; each round consisting of four quarter-rounds.
            Span<uint> workingState = stackalloc uint[BLOCK_SIZE_IN_INTS];
            state.CopyTo(workingState);
            Salsa20Base.ShuffleState(workingState);

            // At the end of the rounds, add the result to the original state.
            for (var i = 0; i < BLOCK_SIZE_IN_INTS; i++)
                state[i] += workingState[i];

            ArrayUtils.StoreArray16UInt32LittleEndian(block, 0, state);
        }

        public void Process(ReadOnlySpan<byte> nonce, Span<byte> output, ReadOnlySpan<byte> input, int offset = 0)
        {
            var blockSizeInBytes = _salsa20.BlockSizeInBytes;
            var length = input.Length;
            var numBlocks = (length / blockSizeInBytes) + 1;

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

            using var owner = MemoryPool<byte>.Shared.Rent(blockSizeInBytes);
            for (var i = 0; i < numBlocks; i++)
            {
                ProcessKeyStreamBlock(nonce, i + _salsa20.InitialCounter, owner.Memory.Span);

                if (i == numBlocks - 1)
                    Xor(output, input, owner.Memory.Span, length % blockSizeInBytes, offset, i); // last block
                else
                    Xor(output, input, owner.Memory.Span, blockSizeInBytes, offset, i);

                owner.Memory.Span.Clear();
            }
        }

        private void Xor(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> block, int len, int offset, int curBlock)
        {
            var blockOffset = curBlock * _salsa20.BlockSizeInBytes;

            // Since is not called directly from outside, there's no need to check
            //if (len < 0 || offset < 0 || curBlock < 0 || output.Length < len || (input.Length - blockOffset) < len || block.Length < len)
            //    throw new CryptographicException("The combination of blocks, offsets and length to be XORed is out-of-bonds.");

            for (var i = 0; i < len; i++)
                output[i + offset + blockOffset] = (byte)(input[i + blockOffset] ^ block[i]);
        }

        /// <summary>
        /// Process a pseudorandom key stream block, converting the key and part of the <paramref name="nonce"/> into a <paramref name="subKey"/>, and the remainder of the <paramref name="nonce"/>.
        /// </summary>
        /// <param name="subKey">The subKey.</param>
        /// <param name="nonce">The nonce.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void HSalsa20(Span<byte> subKey, ReadOnlySpan<byte> nonce)
        {
            // See: http://cr.yp.to/snuffle/xsalsa-20081128.pdf under 2. Specification - Definition of HSalsa20

            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_BYTES];

            // Setting HSalsa20 initial state
            _salsa20.HSalsa20InitialState(state, nonce);

            // Block function
            Salsa20Base.ShuffleState(state);

            state[1] = state[5];
            state[2] = state[10];
            state[3] = state[15];
            state[4] = state[6];
            state[5] = state[7];
            state[6] = state[8];
            state[7] = state[9];

            ArrayUtils.StoreArray8UInt32LittleEndian(subKey, 0, state);
        }
    }
}