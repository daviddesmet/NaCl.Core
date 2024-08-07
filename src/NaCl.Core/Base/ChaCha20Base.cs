namespace NaCl.Core.Base;

using System;
using System.Runtime.CompilerServices;
#if INTRINSICS
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif
using System.Security.Cryptography;

using Internal;

/// <summary>
/// Base class for <see cref="NaCl.Core.ChaCha20" /> and <see cref="NaCl.Core.XChaCha20" />.
/// </summary>
/// <seealso cref="NaCl.Core.Base.Snuffle" />
/// <seealso cref="NaCl.Core.ChaCha20" />
/// <seealso cref="NaCl.Core.XChaCha20" />
public abstract class ChaCha20Base : Snuffle
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ChaCha20Base"/> class.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="initialCounter">The initial counter.</param>
    protected ChaCha20Base(ReadOnlyMemory<byte> key, int initialCounter) : base(key, initialCounter) { }

    /// <inheritdoc />
    public override int BlockSizeInBytes => BLOCK_SIZE_IN_BYTES;

    /// <summary>
    /// Sets the initial <paramref name="state"/> from <paramref name="nonce"/> and <paramref name="counter"/>.
    /// ChaCha20 has a different logic than XChaCha20, because the former uses a 12-byte nonce, but the later uses 24-byte.
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

        // Set the initial state based on https://tools.ietf.org/html/rfc8439#section-2.3
        Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_INTS];
        SetInitialState(state, nonce, counter);

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
        HChaCha20InitialState(state, nonce);

        // Block function
        ShuffleState(state);

        // Final subkey = state[0..4] || state[12..16]
        // state.Slice(12, 4).CopyTo(state.Slice(4, 4));
        state[4] = state[12];
        state[5] = state[13];
        state[6] = state[14];
        state[7] = state[15];

        ArrayUtils.StoreArray8UInt32LittleEndian(subKey, 0, state);
    }

    /// <summary>
    /// Sets the initial <paramref name="state"/> of the HChaCha20 using the key and the <paramref name="nonce"/>.
    /// </summary>
    /// <param name="state">The state.</param>
    /// <param name="nonce">The nonce.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void HChaCha20InitialState(Span<uint> state, ReadOnlySpan<byte> nonce)
    {
        // See https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.

        // Set ChaCha20 constant
        SetSigma(state);

        // Set 256-bit Key
        SetKey(state, Key.Span);

        // Set 128-bit Nonce
        state[12] = ArrayUtils.LoadUInt32LittleEndian(nonce, 0);
        state[13] = ArrayUtils.LoadUInt32LittleEndian(nonce, 4);
        state[14] = ArrayUtils.LoadUInt32LittleEndian(nonce, 8);
        state[15] = ArrayUtils.LoadUInt32LittleEndian(nonce, 12);
    }

    /*
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
                x12 = BitUtils.RotateLeft(x12 ^ x0, 16);
                x8 += x12;
                x4 = BitUtils.RotateLeft(x4 ^ x8, 12);
                x0 += x4;
                x12 = BitUtils.RotateLeft(x12 ^ x0, 8);
                x8 += x12;
                x4 = BitUtils.RotateLeft(x4 ^ x8, 7);

                x1 += x5;
                x13 = BitUtils.RotateLeft(x13 ^ x1, 16);
                x9 += x13;
                x5 = BitUtils.RotateLeft(x5 ^ x9, 12);
                x1 += x5;
                x13 = BitUtils.RotateLeft(x13 ^ x1, 8);
                x9 += x13;
                x5 = BitUtils.RotateLeft(x5 ^ x9, 7);

                x2 += x6;
                x14 = BitUtils.RotateLeft(x14 ^ x2, 16);
                x10 += x14;
                x6 = BitUtils.RotateLeft(x6 ^ x10, 12);
                x2 += x6;
                x14 = BitUtils.RotateLeft(x14 ^ x2, 8);
                x10 += x14;
                x6 = BitUtils.RotateLeft(x6 ^ x10, 7);

                x3 += x7;
                x15 = BitUtils.RotateLeft(x15 ^ x3, 16);
                x11 += x15;
                x7 = BitUtils.RotateLeft(x7 ^ x11, 12);
                x3 += x7;
                x15 = BitUtils.RotateLeft(x15 ^ x3, 8);
                x11 += x15;
                x7 = BitUtils.RotateLeft(x7 ^ x11, 7);

                // Diagonal quarter rounds
                x0 += x5;
                x15 = BitUtils.RotateLeft(x15 ^ x0, 16);
                x10 += x15;
                x5 = BitUtils.RotateLeft(x5 ^ x10, 12);
                x0 += x5;
                x15 = BitUtils.RotateLeft(x15 ^ x0, 8);
                x10 += x15;
                x5 = BitUtils.RotateLeft(x5 ^ x10, 7);

                x1 += x6;
                x12 = BitUtils.RotateLeft(x12 ^ x1, 16);
                x11 += x12;
                x6 = BitUtils.RotateLeft(x6 ^ x11, 12);
                x1 += x6;
                x12 = BitUtils.RotateLeft(x12 ^ x1, 8);
                x11 += x12;
                x6 = BitUtils.RotateLeft(x6 ^ x11, 7);

                x2 += x7;
                x13 = BitUtils.RotateLeft(x13 ^ x2, 16);
                x8 += x13;
                x7 = BitUtils.RotateLeft(x7 ^ x8, 12);
                x2 += x7;
                x13 = BitUtils.RotateLeft(x13 ^ x2, 8);
                x8 += x13;
                x7 = BitUtils.RotateLeft(x7 ^ x8, 7);

                x3 += x4;
                x14 = BitUtils.RotateLeft(x14 ^ x3, 16);
                x9 += x14;
                x4 = BitUtils.RotateLeft(x4 ^ x9, 12);
                x3 += x4;
                x14 = BitUtils.RotateLeft(x14 ^ x3, 8);
                x9 += x14;
                x4 = BitUtils.RotateLeft(x4 ^ x9, 7);
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
    */

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected static void ShuffleState(Span<uint> state)
    {
#if INTRINSICS
        if (Avx2.IsSupported)
        {
            ShuffleStateAvx2(state);
            return;
        }

        if (Sse3.IsSupported)
        {
            ShuffleStateSse3(state);
            return;
        }
#endif

        // 10 loops × 2 rounds/loop = 20 rounds
        for (var i = 0; i < 10; i++)
        {
            // Odd round
            QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);  // column 0
            QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);  // column 1
            QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]); // column 2
            QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]); // column 3

            // Even round
            QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]); // column 1 (main diagonal)
            QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]); // column 2
            QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);  // column 3
            QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);  // column 4
        }
    }

#if INTRINSICS
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected static void ShuffleStateSse3(Span<uint> state)
    {
        if (!Sse3.IsSupported)
            throw new PlatformNotSupportedException("SS3 is not supported on this platform.");

        var s0 = Vector128.Create(state[0], state[1], state[2], state[3]);
        var s1 = Vector128.Create(state[4], state[5], state[6], state[7]);
        var s2 = Vector128.Create(state[8], state[9], state[10], state[11]);
        var s3 = Vector128.Create(state[12], state[13], state[14], state[15]);

        for (var i = 0; i < 10; i++)
        {
            // Odd round
            QuarterRound(ref s0, ref s1, ref s2, ref s3);  // column 0

            // Even round
            QuarterRound(ref s0, ref s1, ref s2, ref s3);  // column 1 (main diagonal)
        }

#if NET8_0_OR_GREATER
        s0.CopyTo(state);
        s1.CopyTo(state[4..]);
        s2.CopyTo(state[8..]);
        s3.CopyTo(state[12..]);
#elif NET6_0
        unsafe
        {
            Sse2.Store((uint*)MemoryMarshal.GetReference(state), s0);
            Sse2.Store((uint*)MemoryMarshal.GetReference(state[4..]), s1);
            Sse2.Store((uint*)MemoryMarshal.GetReference(state[8..]), s2);
            Sse2.Store((uint*)MemoryMarshal.GetReference(state[12..]), s3);
        }
#endif
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected static void ShuffleStateAvx2(Span<uint> state)
    {
        if (!Avx2.IsSupported)
            throw new PlatformNotSupportedException("AVX2 is not supported on this platform.");

        var s0 = Vector256.Create(state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
        var s1 = Vector256.Create(state[8], state[9], state[10], state[11], state[12], state[13], state[14], state[15]);

        for (var i = 0; i < 10; i++)
        {
            // Odd round
            QuarterRound(ref s0, ref s1, ref s0, ref s1);  // column 0

            // Even round
            QuarterRound(ref s0, ref s1, ref s0, ref s1);  // column 1 (main diagonal)
        }

#if NET8_0_OR_GREATER
        s0.CopyTo(state);
        s1.CopyTo(state[8..]);
#elif NET6_0
        unsafe
        {
            var byteSpan = MemoryMarshal.Cast<uint, byte>(state);
            Avx.Store((byte*)MemoryMarshal.GetReference(byteSpan), s0.AsByte());
            Avx.Store((byte*)MemoryMarshal.GetReference(byteSpan[32..]), s1.AsByte());
        }
#endif
    }
#endif

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b;
        d = BitUtils.RotateLeft(d ^ a, 16);
        c += d;
        b = BitUtils.RotateLeft(b ^ c, 12);
        a += b;
        d = BitUtils.RotateLeft(d ^ a, 8);
        c += d;
        b = BitUtils.RotateLeft(b ^ c, 7);
    }

#if INTRINSICS
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void QuarterRound(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
    {
#if NET8_0_OR_GREATER
        a = Sse2.Add(a, b);
        d = Sse2.Xor(d, a);
        d = Sse2.ShiftLeftLogical(d, 16) | Sse2.ShiftRightLogical(d, 16);

        c = Sse2.Add(c, d);
        b = Sse2.Xor(b, c);
        b = Sse2.ShiftLeftLogical(b, 12) | Sse2.ShiftRightLogical(b, 20);

        a = Sse2.Add(a, b);
        d = Sse2.Xor(d, a);
        d = Sse2.ShiftLeftLogical(d, 8) | Sse2.ShiftRightLogical(d, 24);

        c = Sse2.Add(c, d);
        b = Sse2.Xor(b, c);
        b = Sse2.ShiftLeftLogical(b, 7) | Sse2.ShiftRightLogical(b, 25);
#elif NET6_0
        a = Sse2.Add(a, b);
        d = Sse2.Xor(d, a);
        d = Sse2.Or(Sse2.ShiftLeftLogical(d, 16), Sse2.ShiftRightLogical(d, 16));

        c = Sse2.Add(c, d);
        b = Sse2.Xor(b, c);
        b = Sse2.Or(Sse2.ShiftLeftLogical(b, 12), Sse2.ShiftRightLogical(b, 20));

        a = Sse2.Add(a, b);
        d = Sse2.Xor(d, a);
        d = Sse2.Or(Sse2.ShiftLeftLogical(d, 8), Sse2.ShiftRightLogical(d, 24));

        c = Sse2.Add(c, d);
        b = Sse2.Xor(b, c);
        b = Sse2.Or(Sse2.ShiftLeftLogical(b, 7), Sse2.ShiftRightLogical(b, 25));
#endif
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void QuarterRound(ref Vector256<uint> a, ref Vector256<uint> b, ref Vector256<uint> c, ref Vector256<uint> d)
    {
#if NET8_0_OR_GREATER
        a = Avx2.Add(a, b);
        d = Avx2.Xor(d, a);
        d = Avx2.ShiftLeftLogical(d, 16) | Avx2.ShiftRightLogical(d, 16);

        c = Avx2.Add(c, d);
        b = Avx2.Xor(b, c);
        b = Avx2.ShiftLeftLogical(b, 12) | Avx2.ShiftRightLogical(b, 20);

        a = Avx2.Add(a, b);
        d = Avx2.Xor(d, a);
        d = Avx2.ShiftLeftLogical(d, 8) | Avx2.ShiftRightLogical(d, 24);

        c = Avx2.Add(c, d);
        b = Avx2.Xor(b, c);
        b = Avx2.ShiftLeftLogical(b, 7) | Avx2.ShiftRightLogical(b, 25);
#elif NET6_0
        a = Avx2.Add(a, b);
        d = Avx2.Xor(d, a);
        d = Avx2.Or(Avx2.ShiftLeftLogical(d, 16), Avx2.ShiftRightLogical(d, 16));

        c = Avx2.Add(c, d);
        b = Avx2.Xor(b, c);
        b = Avx2.Or(Avx2.ShiftLeftLogical(b, 12), Avx2.ShiftRightLogical(b, 20));

        a = Avx2.Add(a, b);
        d = Avx2.Xor(d, a);
        d = Avx2.Or(Avx2.ShiftLeftLogical(d, 8), Avx2.ShiftRightLogical(d, 24));

        c = Avx2.Add(c, d);
        b = Avx2.Xor(b, c);
        b = Avx2.Or(Avx2.ShiftLeftLogical(b, 7), Avx2.ShiftRightLogical(b, 25));
#endif
    }
#endif

    /// <summary>
    /// Sets the ChaCha20 constant.
    /// </summary>
    /// <param name="state">The state.</param>
    protected static void SetSigma(Span<uint> state)
    {
        // SIGMA.AsSpan()[..4].CopyTo(state);
        state[0] = SIGMA[0];
        state[1] = SIGMA[1];
        state[2] = SIGMA[2];
        state[3] = SIGMA[3];
    }

    /// <summary>
    /// Sets the 256-bit Key.
    /// </summary>
    /// <param name="state">The state.</param>
    /// <param name="key">The key.</param>
    protected static void SetKey(Span<uint> state, ReadOnlySpan<byte> key)
    {
        state[4] = ArrayUtils.LoadUInt32LittleEndian(key, 0);
        state[5] = ArrayUtils.LoadUInt32LittleEndian(key, 4);
        state[6] = ArrayUtils.LoadUInt32LittleEndian(key, 8);
        state[7] = ArrayUtils.LoadUInt32LittleEndian(key, 12);
        state[8] = ArrayUtils.LoadUInt32LittleEndian(key, 16);
        state[9] = ArrayUtils.LoadUInt32LittleEndian(key, 20);
        state[10] = ArrayUtils.LoadUInt32LittleEndian(key, 24);
        state[11] = ArrayUtils.LoadUInt32LittleEndian(key, 28);
    }
}
