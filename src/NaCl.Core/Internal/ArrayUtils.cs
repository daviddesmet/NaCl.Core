namespace NaCl.Core.Internal;

using System;
using System.Buffers.Binary;
#if NET6_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.CompilerServices;
#endif

internal static class ArrayUtils
{
    #region Individual

    /// <summary>
    /// Loads 4 bytes of the input buffer into an unsigned 32-bit integer, beginning at the input offset.
    /// </summary>
    /// <param name="buf">The input buffer.</param>
    /// <param name="offset">The input offset.</param>
    /// <returns>System.UInt32.</returns>
    public static uint LoadUInt32LittleEndian(ReadOnlySpan<byte> buf, int offset)
        => BinaryPrimitives.ReadUInt32LittleEndian(buf.Slice(offset + 0, sizeof(int)));

    /// <summary>
    /// Stores the value into the buffer.
    /// The value will be split into 4 bytes and put into four sequential places in the output buffer, starting at the specified offset.
    /// </summary>
    /// <param name="buf">The output buffer.</param>
    /// <param name="offset">The output offset.</param>
    /// <param name="value">The input value.</param>
    public static void StoreUInt32LittleEndian(Span<byte> buf, int offset, uint value)
        => BinaryPrimitives.WriteUInt32LittleEndian(buf.Slice(offset + 0, sizeof(int)), value);

    /// <summary>
    /// Stores the value into the buffer.
    /// The value will be split into 8 bytes and put into eight sequential places in the output buffer, starting at the specified offset.
    /// </summary>
    /// <param name="buf">The output buffer.</param>
    /// <param name="offset">The output offset.</param>
    /// <param name="value">The input value.</param>
    public static void StoreUInt64LittleEndian(Span<byte> buf, int offset, ulong value)
        => BinaryPrimitives.WriteUInt64LittleEndian(buf.Slice(offset + 0, sizeof(ulong)), value);

    #endregion

    #region Array

    /// <summary>
    /// Stores the byte array in 8 parts split into 4 bytes and places it in the output buffer.
    /// </summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="offset">The starting offset.</param>
    /// <param name="input">The input buffer.</param>
    public static void StoreArray8UInt32LittleEndian(Span<byte> output, int offset, ReadOnlySpan<uint> input)
        => StoreArrayUInt32LittleEndian(output, offset, input, 8);

    /// <summary>
    /// Stores the byte array in 16 parts split into 4 bytes and places it in the output buffer.
    /// </summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="offset">The starting offset.</param>
    /// <param name="input">The input buffer.</param>
    public static void StoreArray16UInt32LittleEndian(Span<byte> output, int offset, ReadOnlySpan<uint> input)
        => StoreArrayUInt32LittleEndian(output, offset, input, 16);

    /// <summary>
    /// Stores the byte array split in n size parts into 4 bytes and places it in the output buffer.
    /// </summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="offset">The starting offset.</param>
    /// <param name="input">The input buffer.</param>
    /// <param name="size">The parts to split the input buffer.</param>
    public static void StoreArrayUInt32LittleEndian(Span<byte> output, int offset, ReadOnlySpan<uint> input, int size)
    {
#if NET6_0_OR_GREATER
        if (Avx2.IsSupported && size >= 8)
        {
            StoreArrayUInt32LittleEndianAvx2(output, offset, input, size);
            return;
        }
        if (Sse2.IsSupported && size >= 4)
        {
            StoreArrayUInt32LittleEndianSse2(output, offset, input, size);
            return;
        }
        if (AdvSimd.IsSupported && size >= 4)
        {
            StoreArrayUInt32LittleEndianAdvSimd(output, offset, input, size);
            return;
        }
#endif
        StoreArrayUInt32LittleEndianScalar(output, offset, input, size);
    }

    /// <summary>
    /// Stores the byte array split in n size parts into 4 bytes and places it in the output buffer using scalar operations.
    /// </summary>
    /// <param name="output">The output buffer.</param>
    /// <param name="offset">The starting offset.</param>
    /// <param name="input">The input buffer.</param>
    /// <param name="size">The parts to split the input buffer.</param>
    private static void StoreArrayUInt32LittleEndianScalar(Span<byte> output, int offset, ReadOnlySpan<uint> input, int size)
    {
        var len = sizeof(int);
        var start = offset + 0;
        for (var i = 0; i < size; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(start, len), input[i]);
            start += len;
        }
    }

#if NET6_0_OR_GREATER
    /// <summary>
    /// Stores the byte array using AVX2 intrinsics for vectorized operations.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void StoreArrayUInt32LittleEndianAvx2(Span<byte> output, int offset, ReadOnlySpan<uint> input, int size)
    {
        fixed (byte* outputPtr = &output[offset])
        fixed (uint* inputPtr = input)
        {
            var i = 0;
            var vectorSize = Vector256<uint>.Count; // 8 elements
            var vectorSizeBytes = vectorSize * sizeof(uint); // 32 bytes

            // Process 8 uint32s (32 bytes) at a time with AVX2
            for (; i + vectorSize <= size; i += vectorSize)
            {
                var vec = Avx.LoadVector256(inputPtr + i);
                Avx.Store(outputPtr + i * sizeof(uint), vec.AsByte());
            }

            // Handle remaining elements with scalar operations
            for (; i < size; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(
                    output.Slice(offset + i * sizeof(uint), sizeof(uint)), 
                    input[i]);
            }
        }
    }

    /// <summary>
    /// Stores the byte array using SSE2 intrinsics for vectorized operations.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void StoreArrayUInt32LittleEndianSse2(Span<byte> output, int offset, ReadOnlySpan<uint> input, int size)
    {
        fixed (byte* outputPtr = &output[offset])
        fixed (uint* inputPtr = input)
        {
            var i = 0;
            var vectorSize = Vector128<uint>.Count; // 4 elements

            // Process 4 uint32s (16 bytes) at a time with SSE2
            for (; i + vectorSize <= size; i += vectorSize)
            {
                var vec = Sse2.LoadVector128(inputPtr + i);
                Sse2.Store(outputPtr + i * sizeof(uint), vec.AsByte());
            }

            // Handle remaining elements with scalar operations
            for (; i < size; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(
                    output.Slice(offset + i * sizeof(uint), sizeof(uint)), 
                    input[i]);
            }
        }
    }

    /// <summary>
    /// Stores the byte array using ARM AdvSIMD intrinsics for vectorized operations.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void StoreArrayUInt32LittleEndianAdvSimd(Span<byte> output, int offset, ReadOnlySpan<uint> input, int size)
    {
        fixed (byte* outputPtr = &output[offset])
        fixed (uint* inputPtr = input)
        {
            var i = 0;
            var vectorSize = Vector128<uint>.Count; // 4 elements

            // Process 4 uint32s (16 bytes) at a time with AdvSIMD
            for (; i + vectorSize <= size; i += vectorSize)
            {
                var vec = AdvSimd.LoadVector128(inputPtr + i);
                AdvSimd.Store(outputPtr + i * sizeof(uint), vec.AsByte());
            }

            // Handle remaining elements with scalar operations
            for (; i < size; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(
                    output.Slice(offset + i * sizeof(uint), sizeof(uint)), 
                    input[i]);
            }
        }
    }

    /// <summary>
    /// Loads multiple uint32 values from a byte buffer using vectorized operations when possible.
    /// </summary>
    /// <param name="input">The input byte buffer.</param>
    /// <param name="offset">The starting offset in the input buffer.</param>
    /// <param name="output">The output uint32 buffer.</param>
    /// <param name="size">The number of uint32 values to load.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void LoadArrayUInt32LittleEndian(ReadOnlySpan<byte> input, int offset, Span<uint> output, int size)
    {
        if (Avx2.IsSupported && size >= 8)
        {
            LoadArrayUInt32LittleEndianAvx2(input, offset, output, size);
            return;
        }
        if (Sse2.IsSupported && size >= 4)
        {
            LoadArrayUInt32LittleEndianSse2(input, offset, output, size);
            return;
        }
        if (AdvSimd.IsSupported && size >= 4)
        {
            LoadArrayUInt32LittleEndianAdvSimd(input, offset, output, size);
            return;
        }
        
        LoadArrayUInt32LittleEndianScalar(input, offset, output, size);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void LoadArrayUInt32LittleEndianScalar(ReadOnlySpan<byte> input, int offset, Span<uint> output, int size)
    {
        for (var i = 0; i < size; i++)
        {
            output[i] = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(offset + i * sizeof(uint), sizeof(uint)));
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void LoadArrayUInt32LittleEndianAvx2(ReadOnlySpan<byte> input, int offset, Span<uint> output, int size)
    {
        fixed (byte* inputPtr = &input[offset])
        fixed (uint* outputPtr = output)
        {
            var i = 0;
            var vectorSize = Vector256<uint>.Count; // 8 elements

            // Process 8 uint32s (32 bytes) at a time with AVX2
            for (; i + vectorSize <= size; i += vectorSize)
            {
                var vec = Avx.LoadVector256(inputPtr + i * sizeof(uint));
                Avx.Store(outputPtr + i, vec.AsUInt32());
            }

            // Handle remaining elements with scalar operations
            for (; i < size; i++)
            {
                output[i] = BinaryPrimitives.ReadUInt32LittleEndian(
                    input.Slice(offset + i * sizeof(uint), sizeof(uint)));
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void LoadArrayUInt32LittleEndianSse2(ReadOnlySpan<byte> input, int offset, Span<uint> output, int size)
    {
        fixed (byte* inputPtr = &input[offset])
        fixed (uint* outputPtr = output)
        {
            var i = 0;
            var vectorSize = Vector128<uint>.Count; // 4 elements

            // Process 4 uint32s (16 bytes) at a time with SSE2
            for (; i + vectorSize <= size; i += vectorSize)
            {
                var vec = Sse2.LoadVector128(inputPtr + i * sizeof(uint));
                Sse2.Store(outputPtr + i, vec.AsUInt32());
            }

            // Handle remaining elements with scalar operations
            for (; i < size; i++)
            {
                output[i] = BinaryPrimitives.ReadUInt32LittleEndian(
                    input.Slice(offset + i * sizeof(uint), sizeof(uint)));
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void LoadArrayUInt32LittleEndianAdvSimd(ReadOnlySpan<byte> input, int offset, Span<uint> output, int size)
    {
        fixed (byte* inputPtr = &input[offset])
        fixed (uint* outputPtr = output)
        {
            var i = 0;
            var vectorSize = Vector128<uint>.Count; // 4 elements

            // Process 4 uint32s (16 bytes) at a time with AdvSIMD
            for (; i + vectorSize <= size; i += vectorSize)
            {
                var vec = AdvSimd.LoadVector128(inputPtr + i * sizeof(uint));
                AdvSimd.Store(outputPtr + i, vec.AsUInt32());
            }

            // Handle remaining elements with scalar operations
            for (; i < size; i++)
            {
                output[i] = BinaryPrimitives.ReadUInt32LittleEndian(
                    input.Slice(offset + i * sizeof(uint), sizeof(uint)));
            }
        }
    }
#endif

    #endregion
}