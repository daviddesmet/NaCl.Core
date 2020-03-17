namespace NaCl.Core.Internal
{
    using System;
    using System.Buffers.Binary;

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
        public static void StoreUI32LittleEndian(Span<byte> buf, int offset, uint value)
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

        public static void StoreArray8UInt32LittleEndian(Span<byte> output, int offset, ReadOnlySpan<uint> input)
        {
            var len = sizeof(int);

            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 0, len), input[0]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 4, len), input[1]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 8, len), input[2]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 12, len), input[3]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 16, len), input[4]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 20, len), input[5]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 24, len), input[6]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 28, len), input[7]);
        }

        public static void StoreArray16UInt32LittleEndian(Span<byte> output, int offset, ReadOnlySpan<uint> input)
        {
            var len = sizeof(int);

            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 0, len), input[0]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 4, len), input[1]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 8, len), input[2]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 12, len), input[3]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 16, len), input[4]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 20, len), input[5]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 24, len), input[6]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 28, len), input[7]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 32, len), input[8]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 36, len), input[9]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 40, len), input[10]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 44, len), input[11]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 48, len), input[12]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 52, len), input[13]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 56, len), input[14]);
            BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(offset + 60, len), input[15]);
        }

        #endregion
    }
}
