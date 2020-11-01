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
            => StoreArrayUInt32LittleEndian(output, offset, input, 8);

        public static void StoreArray16UInt32LittleEndian(Span<byte> output, int offset, ReadOnlySpan<uint> input)
            => StoreArrayUInt32LittleEndian(output, offset, input, 16);

        public static void StoreArrayUInt32LittleEndian(Span<byte> output, int offset, ReadOnlySpan<uint> input, int size)
        {
            var len = sizeof(int);

            var start = offset + 0;
            for (var i = 0; i < size; i++)
            {
                BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(start, len), input[i]);
                start += len;
            }
        }

        #endregion
    }
}
