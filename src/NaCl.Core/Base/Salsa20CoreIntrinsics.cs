#if INTRINSICS
namespace NaCl.Core.Base
{
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    using Internal;

    internal class Salsa20CoreIntrinsics : ISalsa20Core
    {
        protected const int KEY_SIZE_IN_INTS = 8;
        public const int KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4; // 32
        protected const int BLOCK_SIZE_IN_INTS = 16;
        public const int BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4; // 64

        protected static uint[] SIGMA = new uint[] { 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574 }; // "expand 32-byte k" (4 words constant: "expa", "nd 3", "2-by", and "te k")
        private readonly Salsa20Base _salsa20;

        public Salsa20CoreIntrinsics(Salsa20Base salsa20) => _salsa20 = salsa20;

        public void ProcessKeyStreamBlock(ReadOnlySpan<byte> nonce, int counter, Span<byte> block)
        {
            if (block.Length != BLOCK_SIZE_IN_BYTES)
                throw new CryptographicException($"The key stream block length is not valid. The length in bytes must be {BLOCK_SIZE_IN_BYTES}.");

            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
            _salsa20.SetInitialState(state, nonce, counter);

            Salsa20BaseIntrinsics.Salsa20KeyStream(state, block);
        }

        public unsafe void Process(ReadOnlySpan<byte> nonce, Span<byte> output, ReadOnlySpan<byte> input, int offset = 0)
        {
            Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
            _salsa20.SetInitialState(state, nonce, _salsa20.InitialCounter);
            fixed (uint* x = state)
            fixed (byte* m = input, c = output.Slice(offset))
            {
                Salsa20BaseIntrinsics.Salsa20(x, m, c, (ulong)input.Length);
            }
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

            Salsa20BaseIntrinsics.HSalsa20(state, subKey);
        }
    }
}
#endif