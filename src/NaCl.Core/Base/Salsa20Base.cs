namespace NaCl.Core.Base;

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
#if NET6_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
#endif

using Internal;

/// <summary>
/// Base class for <see cref="NaCl.Core.Salsa20" /> and <see cref="NaCl.Core.XSalsa20" />.
/// </summary>
/// <seealso cref="NaCl.Core.Base.Snuffle" />
/// <seealso cref="NaCl.Core.Salsa20" />
/// <seealso cref="NaCl.Core.XSalsa20" />
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
    public void HSalsa20(Span<byte> subKey, ReadOnlySpan<byte> nonce)
    {
        // See: http://cr.yp.to/snuffle/xsalsa-20081128.pdf under 2. Specification - Definition of HSalsa20

        Span<uint> state = stackalloc uint[BLOCK_SIZE_IN_BYTES];

        // Setting HSalsa20 initial state
        HSalsa20InitialState(state, nonce);

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
#if NET6_0_OR_GREATER
        if (Avx2.IsSupported && state.Length == BLOCK_SIZE_IN_INTS)
        {
            ShuffleStateAvx2(state);
            return;
        }
        if (Sse2.IsSupported && state.Length == BLOCK_SIZE_IN_INTS)
        {
            ShuffleStateSse2(state);
            return;
        }
        if (AdvSimd.IsSupported && state.Length == BLOCK_SIZE_IN_INTS)
        {
            ShuffleStateAdvSimd(state);
            return;
        }
#endif
        ShuffleStateScalar(state);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected static void ShuffleStateScalar(Span<uint> state)
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

#if NET6_0_OR_GREATER
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected static unsafe void ShuffleStateAvx2(Span<uint> state)
    {
        fixed (uint* statePtr = state)
        {
            var s0 = Avx.LoadVector256(statePtr + 0);
            var s1 = Avx.LoadVector256(statePtr + 8);

            // 10 loops × 2 rounds/loop = 20 rounds
            for (var i = 0; i < 10; i++)
            {
                // Odd round - column operations
                QuarterRoundAvx2(ref s0, ref s1, 0, 4, 8, 12);
                QuarterRoundAvx2(ref s0, ref s1, 5, 9, 13, 1);
                QuarterRoundAvx2(ref s0, ref s1, 10, 14, 2, 6);
                QuarterRoundAvx2(ref s0, ref s1, 15, 3, 7, 11);

                // Even round - row operations
                QuarterRoundAvx2(ref s0, ref s1, 0, 1, 2, 3);
                QuarterRoundAvx2(ref s0, ref s1, 5, 6, 7, 4);
                QuarterRoundAvx2(ref s0, ref s1, 10, 11, 8, 9);
                QuarterRoundAvx2(ref s0, ref s1, 15, 12, 13, 14);
            }

            Avx.Store(statePtr + 0, s0);
            Avx.Store(statePtr + 8, s1);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected static unsafe void ShuffleStateSse2(Span<uint> state)
    {
        fixed (uint* statePtr = state)
        {
            var s0 = Sse2.LoadVector128(statePtr + 0);
            var s1 = Sse2.LoadVector128(statePtr + 4);
            var s2 = Sse2.LoadVector128(statePtr + 8);
            var s3 = Sse2.LoadVector128(statePtr + 12);

            // 10 loops × 2 rounds/loop = 20 rounds
            for (var i = 0; i < 10; i++)
            {
                // Odd round - column operations
                QuarterRoundSse2(ref s0, ref s1, ref s2, ref s3, 0, 4, 8, 12);
                QuarterRoundSse2(ref s0, ref s1, ref s2, ref s3, 5, 9, 13, 1);
                QuarterRoundSse2(ref s0, ref s1, ref s2, ref s3, 10, 14, 2, 6);
                QuarterRoundSse2(ref s0, ref s1, ref s2, ref s3, 15, 3, 7, 11);

                // Even round - row operations
                QuarterRoundSse2(ref s0, ref s1, ref s2, ref s3, 0, 1, 2, 3);
                QuarterRoundSse2(ref s0, ref s1, ref s2, ref s3, 5, 6, 7, 4);
                QuarterRoundSse2(ref s0, ref s1, ref s2, ref s3, 10, 11, 8, 9);
                QuarterRoundSse2(ref s0, ref s1, ref s2, ref s3, 15, 12, 13, 14);
            }

            Sse2.Store(statePtr + 0, s0);
            Sse2.Store(statePtr + 4, s1);
            Sse2.Store(statePtr + 8, s2);
            Sse2.Store(statePtr + 12, s3);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected static unsafe void ShuffleStateAdvSimd(Span<uint> state)
    {
        fixed (uint* statePtr = state)
        {
            var s0 = AdvSimd.LoadVector128(statePtr + 0);
            var s1 = AdvSimd.LoadVector128(statePtr + 4);
            var s2 = AdvSimd.LoadVector128(statePtr + 8);
            var s3 = AdvSimd.LoadVector128(statePtr + 12);

            // 10 loops × 2 rounds/loop = 20 rounds
            for (var i = 0; i < 10; i++)
            {
                // Odd round - column operations
                QuarterRoundAdvSimd(ref s0, ref s1, ref s2, ref s3, 0, 4, 8, 12);
                QuarterRoundAdvSimd(ref s0, ref s1, ref s2, ref s3, 5, 9, 13, 1);
                QuarterRoundAdvSimd(ref s0, ref s1, ref s2, ref s3, 10, 14, 2, 6);
                QuarterRoundAdvSimd(ref s0, ref s1, ref s2, ref s3, 15, 3, 7, 11);

                // Even round - row operations
                QuarterRoundAdvSimd(ref s0, ref s1, ref s2, ref s3, 0, 1, 2, 3);
                QuarterRoundAdvSimd(ref s0, ref s1, ref s2, ref s3, 5, 6, 7, 4);
                QuarterRoundAdvSimd(ref s0, ref s1, ref s2, ref s3, 10, 11, 8, 9);
                QuarterRoundAdvSimd(ref s0, ref s1, ref s2, ref s3, 15, 12, 13, 14);
            }

            AdvSimd.Store(statePtr + 0, s0);
            AdvSimd.Store(statePtr + 4, s1);
            AdvSimd.Store(statePtr + 8, s2);
            AdvSimd.Store(statePtr + 12, s3);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRoundAvx2(ref Vector256<uint> s0, ref Vector256<uint> s1, int a, int b, int c, int d)
    {
        var va = GetElementAvx2(s0, s1, a);
        var vb = GetElementAvx2(s0, s1, b);
        var vc = GetElementAvx2(s0, s1, c);
        var vd = GetElementAvx2(s0, s1, d);

        vb = Avx2.Xor(vb, BitUtils.RotateLeftVector256(Avx2.Add(va, vd), 7));
        vc = Avx2.Xor(vc, BitUtils.RotateLeftVector256(Avx2.Add(vb, va), 9));
        vd = Avx2.Xor(vd, BitUtils.RotateLeftVector256(Avx2.Add(vc, vb), 13));
        va = Avx2.Xor(va, BitUtils.RotateLeftVector256(Avx2.Add(vd, vc), 18));

        SetElementAvx2(ref s0, ref s1, a, va);
        SetElementAvx2(ref s0, ref s1, b, vb);
        SetElementAvx2(ref s0, ref s1, c, vc);
        SetElementAvx2(ref s0, ref s1, d, vd);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRoundSse2(ref Vector128<uint> s0, ref Vector128<uint> s1, ref Vector128<uint> s2, ref Vector128<uint> s3, int a, int b, int c, int d)
    {
        var va = GetElementSse2(s0, s1, s2, s3, a);
        var vb = GetElementSse2(s0, s1, s2, s3, b);
        var vc = GetElementSse2(s0, s1, s2, s3, c);
        var vd = GetElementSse2(s0, s1, s2, s3, d);

        vb = Sse2.Xor(vb, BitUtils.RotateLeftVector128(Sse2.Add(va, vd), 7));
        vc = Sse2.Xor(vc, BitUtils.RotateLeftVector128(Sse2.Add(vb, va), 9));
        vd = Sse2.Xor(vd, BitUtils.RotateLeftVector128(Sse2.Add(vc, vb), 13));
        va = Sse2.Xor(va, BitUtils.RotateLeftVector128(Sse2.Add(vd, vc), 18));

        SetElementSse2(ref s0, ref s1, ref s2, ref s3, a, va);
        SetElementSse2(ref s0, ref s1, ref s2, ref s3, b, vb);
        SetElementSse2(ref s0, ref s1, ref s2, ref s3, c, vc);
        SetElementSse2(ref s0, ref s1, ref s2, ref s3, d, vd);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRoundAdvSimd(ref Vector128<uint> s0, ref Vector128<uint> s1, ref Vector128<uint> s2, ref Vector128<uint> s3, int a, int b, int c, int d)
    {
        var va = GetElementAdvSimd(s0, s1, s2, s3, a);
        var vb = GetElementAdvSimd(s0, s1, s2, s3, b);
        var vc = GetElementAdvSimd(s0, s1, s2, s3, c);
        var vd = GetElementAdvSimd(s0, s1, s2, s3, d);

        vb = AdvSimd.Xor(vb, BitUtils.RotateLeftAdvSimd(AdvSimd.Add(va, vd), 7));
        vc = AdvSimd.Xor(vc, BitUtils.RotateLeftAdvSimd(AdvSimd.Add(vb, va), 9));
        vd = AdvSimd.Xor(vd, BitUtils.RotateLeftAdvSimd(AdvSimd.Add(vc, vb), 13));
        va = AdvSimd.Xor(va, BitUtils.RotateLeftAdvSimd(AdvSimd.Add(vd, vc), 18));

        SetElementAdvSimd(ref s0, ref s1, ref s2, ref s3, a, va);
        SetElementAdvSimd(ref s0, ref s1, ref s2, ref s3, b, vb);
        SetElementAdvSimd(ref s0, ref s1, ref s2, ref s3, c, vc);
        SetElementAdvSimd(ref s0, ref s1, ref s2, ref s3, d, vd);
    }

    // Helper methods for vector element access
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> GetElementAvx2(Vector256<uint> s0, Vector256<uint> s1, int index)
    {
        var scalar = index < 8 ? s0.GetElement(index) : s1.GetElement(index - 8);
        return Vector256.Create(scalar);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SetElementAvx2(ref Vector256<uint> s0, ref Vector256<uint> s1, int index, Vector256<uint> value)
    {
        var scalar = value.GetElement(0);
        if (index < 8)
        {
            s0 = s0.WithElement(index, scalar);
        }
        else
        {
            s1 = s1.WithElement(index - 8, scalar);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> GetElementSse2(Vector128<uint> s0, Vector128<uint> s1, Vector128<uint> s2, Vector128<uint> s3, int index)
    {
        return index switch
        {
            < 4 => Vector128.Create(s0.GetElement(index)),
            < 8 => Vector128.Create(s1.GetElement(index - 4)),
            < 12 => Vector128.Create(s2.GetElement(index - 8)),
            _ => Vector128.Create(s3.GetElement(index - 12))
        };
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SetElementSse2(ref Vector128<uint> s0, ref Vector128<uint> s1, ref Vector128<uint> s2, ref Vector128<uint> s3, int index, Vector128<uint> value)
    {
        var scalar = value.GetElement(0);
        switch (index)
        {
            case < 4: s0 = s0.WithElement(index, scalar); break;
            case < 8: s1 = s1.WithElement(index - 4, scalar); break;
            case < 12: s2 = s2.WithElement(index - 8, scalar); break;
            default: s3 = s3.WithElement(index - 12, scalar); break;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> GetElementAdvSimd(Vector128<uint> s0, Vector128<uint> s1, Vector128<uint> s2, Vector128<uint> s3, int index)
    {
        return index switch
        {
            < 4 => Vector128.Create(s0.GetElement(index)),
            < 8 => Vector128.Create(s1.GetElement(index - 4)),
            < 12 => Vector128.Create(s2.GetElement(index - 8)),
            _ => Vector128.Create(s3.GetElement(index - 12))
        };
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SetElementAdvSimd(ref Vector128<uint> s0, ref Vector128<uint> s1, ref Vector128<uint> s2, ref Vector128<uint> s3, int index, Vector128<uint> value)
    {
        var scalar = value.GetElement(0);
        switch (index)
        {
            case < 4: s0 = s0.WithElement(index, scalar); break;
            case < 8: s1 = s1.WithElement(index - 4, scalar); break;
            case < 12: s2 = s2.WithElement(index - 8, scalar); break;
            default: s3 = s3.WithElement(index - 12, scalar); break;
        }
    }
#endif

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