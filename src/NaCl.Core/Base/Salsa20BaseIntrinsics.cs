#if INTRINSICS
namespace NaCl.Core.Base;

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using NaCl.Core.Base.SalsaIntrinsics;

internal static class Salsa20BaseIntrinsics
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Salsa20(Span<uint> state, ReadOnlySpan<byte> input, Span<byte> output, ulong bytes)
    {
        ValidateDeviceSupport();

        fixed (uint* x = state)
        fixed (byte* m_p = input, c_p = output)
        {
            var m = m_p;
            var c = c_p;

            if (Avx2.IsSupported && bytes >= 512)
            {
                Salsa512.Process(x, ref m, ref c, ref bytes);
            }
            if (bytes >= 256)
            {
                Salsa256.Process(x, ref m, ref c, ref bytes);
            }
            while (bytes >= 64)
            {
                Salsa64.Process64(x, ref m, ref c, ref bytes);
            }
            if (bytes > 0)
            {
                Salsa64.ProcessVarLength(x, ref m, ref c, ref bytes);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void HSalsa20(ReadOnlySpan<uint> state, Span<byte> subKey)
    {
        ValidateDeviceSupport();

        fixed (uint* x = state)
        fixed (byte* sk = subKey)
        {
            Salsa64.HSalsa20(x, sk);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Salsa20KeyStream(ReadOnlySpan<uint> state, Span<byte> output)
    {
        ValidateDeviceSupport();

        fixed (byte* c = output)
        fixed (uint* x = state)
        {
            Salsa64.KeyStream64(x, c);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ValidateDeviceSupport()
    {
        if (!Sse3.IsSupported || !BitConverter.IsLittleEndian)
            throw new NotSupportedException($"{nameof(Sse3)} vectorisation is not supported on this device.");
    }
}
#endif