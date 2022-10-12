#if INTRINSICS

using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using NaCl.Core.Base.ChaChaIntrinsics;

namespace NaCl.Core.Base;

public static class ChaCha20BaseIntrinsics
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void ChaCha20(uint* x, byte* m, byte* c, ulong bytes)
    {
        if (!Sse3.IsSupported)
            throw new Exception("Error this vectorisation is not supported on this CPU");

        if (Avx2.IsSupported && bytes >= 512)
        {
            ChaCha512.Process(x, ref m, ref c, ref bytes);
        }
        if (bytes >= 256)
        {
            ChaCha256.Process(x, ref m, ref c, ref bytes);
        }
        while (bytes >= 64)
        {
            ChaCha64.Process64(x, ref m, ref c, ref bytes);
        }
        if (bytes > 0)
        {
            ChaCha64.ProcessVarLength(x, ref m, ref c, ref bytes);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void HChaCha20(Span<byte> subKey, ReadOnlySpan<uint> state)
    {
        if (!Sse3.IsSupported)
            throw new Exception("Error this vectorisation is not supported on this CPU");
        ChaCha64.HChaCha20(subKey, state);
    }
}
#endif