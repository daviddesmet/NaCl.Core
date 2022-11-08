#if INTRINSICS
namespace NaCl.Core.Base.SalsaCore;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Internal;

internal class Salsa20CoreIntrinsics : ISalsa20Core
{
    const int BLOCK_SIZE_IN_BYTES = Snuffle.BLOCK_SIZE_IN_BYTES;
    const int BLOCK_SIZE_IN_INTS = Snuffle.BLOCK_SIZE_IN_INTS;

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

        Salsa20BaseIntrinsics.Salsa20(state, input, output[offset..], (ulong)input.Length);
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
#endif