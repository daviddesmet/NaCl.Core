﻿#if INTRINSICS
namespace NaCl.Core.Base;

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;


internal class ChaCha20CoreIntrinsics : IChaCha20Core
{
    const int BLOCK_SIZE_IN_BYTES = Snuffle.BLOCK_SIZE_IN_BYTES;
    const int BLOCK_SIZE_IN_INTS = Snuffle.BLOCK_SIZE_IN_INTS;

    private readonly ChaCha20Base _chaCha20;
    public ChaCha20CoreIntrinsics(ChaCha20Base chaCha20Base) => _chaCha20=chaCha20Base;

    public void ProcessKeyStreamBlock(ReadOnlySpan<byte> nonce, int counter, Span<byte> block)
    {
        if (block.Length != BLOCK_SIZE_IN_BYTES)
            throw new CryptographicException($"The key stream block length is not valid. The length in bytes must be {BLOCK_SIZE_IN_BYTES}.");

        // Set the initial state based on https://tools.ietf.org/html/rfc8439#section-2.3
        Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
        _chaCha20.SetInitialState(state, nonce, counter);

        ChaCha20BaseIntrinsics.ChaCha20KeyStream(state, block);
    }

    public unsafe void Process(ReadOnlySpan<byte> nonce, Span<byte> output, ReadOnlySpan<byte> input, int offset = 0)
    {
        Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
        _chaCha20.SetInitialState(state, nonce, _chaCha20.InitialCounter);
        
        fixed(uint* x = state)
        fixed (byte* m = input, c = output.Slice(offset))
        {
            ChaCha20BaseIntrinsics.ChaCha20(x, m, c, (ulong)input.Length);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void HChaCha20(Span<byte> subKey, ReadOnlySpan<byte> nonce)
    {
        // See https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.
        Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];

        // Setting HChaCha20 initial state
        _chaCha20.HChaCha20InitialState(state, nonce);

        ChaCha20BaseIntrinsics.HChaCha20(state, subKey);
    }
}
#endif