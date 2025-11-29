namespace NaCl.Core.Internal;

using System;
using System.Runtime.CompilerServices;
#if NET6_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
#endif

internal static class BitUtils
{
    /// <summary>
    /// Rotates the specified value left by the specified number of bits.
    /// </summary>
    /// <param name="value">The value to rotate.</param>
    /// <param name="offset">The number of bits to rotate by.</param>
    /// <returns>The rotated value.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateLeft(uint value, int offset)
    {
#if FCL_BITOPS
        return System.Numerics.BitOperations.RotateLeft(value, offset);
#else
        return (value << offset) | (value >> (32 - offset));
#endif
    }

    /// <summary>
    /// Rotates the specified value left by the specified number of bits.
    /// </summary>
    /// <param name="value">The value to rotate.</param>
    /// <param name="offset">The number of bits to rotate by.</param>
    /// <returns>The rotated value.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateLeft(ulong value, int offset) // Taken help from: https://stackoverflow.com/a/48580489/5592276
    {
#if FCL_BITOPS
        return System.Numerics.BitOperations.RotateLeft(value, offset);
#else
        return (value << offset) | (value >> (64 - offset));
#endif
    }

#if NET6_0_OR_GREATER
    /// <summary>
    /// Rotates the specified Vector128 value left by 16 bits.
    /// </summary>
    /// <param name="value">The value to rotate.</param>
    /// <param name="offset">The number of bits to rotate by.</param>
    /// <returns>The rotated value.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<uint> RotateLeftVector128(Vector128<uint> value, int offset) => offset switch
    {
        // ChaCha20 rotations
        16 => Sse2.Or(Sse2.ShiftLeftLogical(value, 16), Sse2.ShiftRightLogical(value, 16)),
        12 => Sse2.Or(Sse2.ShiftLeftLogical(value, 12), Sse2.ShiftRightLogical(value, 20)),
        8 => Sse2.Or(Sse2.ShiftLeftLogical(value, 8), Sse2.ShiftRightLogical(value, 24)),
        7 => Sse2.Or(Sse2.ShiftLeftLogical(value, 7), Sse2.ShiftRightLogical(value, 25)),
        // Salsa20 rotations
        18 => Sse2.Or(Sse2.ShiftLeftLogical(value, 18), Sse2.ShiftRightLogical(value, 14)),
        13 => Sse2.Or(Sse2.ShiftLeftLogical(value, 13), Sse2.ShiftRightLogical(value, 19)),
        9 => Sse2.Or(Sse2.ShiftLeftLogical(value, 9), Sse2.ShiftRightLogical(value, 23)),
        _ => throw new ArgumentException($"Unsupported rotation offset: {offset}")
    };

    /// <summary>
    /// Rotates the specified Vector256 value left by the specified number of bits.
    /// </summary>
    /// <param name="value">The value to rotate.</param>
    /// <param name="offset">The number of bits to rotate by.</param>
    /// <returns>The rotated value.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector256<uint> RotateLeftVector256(Vector256<uint> value, int offset) => offset switch
    {
        // ChaCha20 rotations
        16 => Avx2.Or(Avx2.ShiftLeftLogical(value, 16), Avx2.ShiftRightLogical(value, 16)),
        12 => Avx2.Or(Avx2.ShiftLeftLogical(value, 12), Avx2.ShiftRightLogical(value, 20)),
        8 => Avx2.Or(Avx2.ShiftLeftLogical(value, 8), Avx2.ShiftRightLogical(value, 24)),
        7 => Avx2.Or(Avx2.ShiftLeftLogical(value, 7), Avx2.ShiftRightLogical(value, 25)),
        // Salsa20 rotations
        18 => Avx2.Or(Avx2.ShiftLeftLogical(value, 18), Avx2.ShiftRightLogical(value, 14)),
        13 => Avx2.Or(Avx2.ShiftLeftLogical(value, 13), Avx2.ShiftRightLogical(value, 19)),
        9 => Avx2.Or(Avx2.ShiftLeftLogical(value, 9), Avx2.ShiftRightLogical(value, 23)),
        _ => throw new ArgumentException($"Unsupported rotation offset: {offset}")
    };

    /// <summary>
    /// Rotates the specified Vector128 value left by the specified number of bits using ARM AdvSIMD.
    /// </summary>
    /// <param name="value">The value to rotate.</param>
    /// <param name="offset">The number of bits to rotate by.</param>
    /// <returns>The rotated value.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<uint> RotateLeftAdvSimd(Vector128<uint> value, int offset) => offset switch
    {
        // ChaCha20 rotations
        16 => AdvSimd.Or(AdvSimd.ShiftLeftLogical(value, 16), AdvSimd.ShiftRightLogical(value, 16)),
        12 => AdvSimd.Or(AdvSimd.ShiftLeftLogical(value, 12), AdvSimd.ShiftRightLogical(value, 20)),
        8 => AdvSimd.Or(AdvSimd.ShiftLeftLogical(value, 8), AdvSimd.ShiftRightLogical(value, 24)),
        7 => AdvSimd.Or(AdvSimd.ShiftLeftLogical(value, 7), AdvSimd.ShiftRightLogical(value, 25)),
        // Salsa20 rotations
        18 => AdvSimd.Or(AdvSimd.ShiftLeftLogical(value, 18), AdvSimd.ShiftRightLogical(value, 14)),
        13 => AdvSimd.Or(AdvSimd.ShiftLeftLogical(value, 13), AdvSimd.ShiftRightLogical(value, 19)),
        9 => AdvSimd.Or(AdvSimd.ShiftLeftLogical(value, 9), AdvSimd.ShiftRightLogical(value, 23)),
        _ => throw new ArgumentException($"Unsupported rotation offset: {offset}")
    };
#endif
}