#if INTRINSICS

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using NaCl.Core.Base.SalsaIntrinsics;

namespace NaCl.Core.Base;

public static class Salsa20BaseIntrinsics
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Salsa20(uint* x, byte* m, byte* c, ulong bytes)
    {
        if (!Sse3.IsSupported)
            throw new Exception("Error this vectorisation is not supported on this CPU");

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void HSalsa20(Span<byte> subKey, ReadOnlySpan<uint> state)
    {
        if (!Sse3.IsSupported)
            throw new Exception("Error this vectorisation is not supported on this CPU");
        Salsa64.HSalsa20(subKey, state);
    }
}
#endif