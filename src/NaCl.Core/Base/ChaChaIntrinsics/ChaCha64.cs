#if INTRINSICS
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System;

namespace NaCl.Core.Base.ChaChaIntrinsics;

#pragma warning disable IDE0007 // Use implicit type
internal static class ChaCha64
{
    private static readonly Vector128<byte> rot8_128 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
    private static readonly Vector128<byte> rot16_128 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Process64(uint* x, ref byte* m, ref byte* c, ref ulong bytes)
    {
        Vector128<uint> x_0 =Sse2.LoadVector128(x);
        Vector128<uint> x_1 =Sse2.LoadVector128(x + 4);
        Vector128<uint> x_2 =Sse2.LoadVector128(x + 8);
        Vector128<uint> x_3 =Sse2.LoadVector128(x + 12);

        Vector128<uint> orig_0 = x_0;
        Vector128<uint> orig_1 = x_1;
        Vector128<uint> orig_2 = x_2;
        Vector128<uint> orig_3 = x_3;

        ShuffleState(ref x_0, ref x_1, ref x_2, ref x_3);

        x_0 = Sse2.Add(x_0, orig_0);
        x_1 = Sse2.Add(x_1, orig_1);
        x_2 = Sse2.Add(x_2, orig_2);
        x_3 = Sse2.Add(x_3, orig_3);

        x_0 = Sse2.Xor(x_0.AsByte(), Sse2.LoadVector128(m)).AsUInt32();
        x_1 = Sse2.Xor(x_1.AsByte(), Sse2.LoadVector128(m + 16)).AsUInt32();
        x_2 = Sse2.Xor(x_2.AsByte(), Sse2.LoadVector128(m + 32)).AsUInt32();
        x_3 = Sse2.Xor(x_3.AsByte(), Sse2.LoadVector128(m + 48)).AsUInt32();
        Sse2.Store(c, x_0.AsByte());
        Sse2.Store(c + 16, x_1.AsByte());
        Sse2.Store(c + 32, x_2.AsByte());
        Sse2.Store(c + 48, x_3.AsByte());

        uint in12 = x[12];
        uint in13 = x[13];
        in12++;
        if (in12 == 0)
        {
            in13++;
        }
        x[12] = in12;
        x[13] = in13;

        bytes -= 64;
        c += 64;
        m += 64;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void ProcessVarLength(uint* x, ref byte* m, ref byte* c, ref ulong bytes)
    {
        Vector128<uint> x_0 = Sse2.LoadVector128(x);
        Vector128<uint> x_1 = Sse2.LoadVector128(x + 4);
        Vector128<uint> x_2 = Sse2.LoadVector128(x + 8);
        Vector128<uint> x_3 = Sse2.LoadVector128(x + 12);

        Vector128<uint> orig_0 = x_0;
        Vector128<uint> orig_1 = x_1;
        Vector128<uint> orig_2 = x_2;
        Vector128<uint> orig_3 = x_3;

        ShuffleState(ref x_0, ref x_1, ref x_2, ref x_3);

        x_0 = Sse2.Add(x_0, orig_0);
        x_1 = Sse2.Add(x_1, orig_1);
        x_2 = Sse2.Add(x_2, orig_2);
        x_3 = Sse2.Add(x_3, orig_3);

        byte* partialblock = stackalloc byte[64];
        Sse2.Store(partialblock, Vector128.AsByte(x_0));
        Sse2.Store(partialblock + 16, Vector128.AsByte(x_1));
        Sse2.Store(partialblock + 32, Vector128.AsByte(x_2));
        Sse2.Store(partialblock + 48, Vector128.AsByte(x_3));

        for (ulong i = 0; i<bytes; i++)
        {
            c[i] = (byte)(m[i] ^ partialblock[i]);
        }
        for (int n = 0; n < 64 / sizeof(int); n++)
        {
            ((int*)partialblock)[n] = 0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void HChaCha20(Span<byte> subKey, ReadOnlySpan<uint> state)
    {
        fixed(uint* x = state)
        fixed(byte* sk = subKey)
        {
            Vector128<uint> x_0 = Sse2.LoadVector128(x);
            Vector128<uint> x_1 = Sse2.LoadVector128(x + 4);
            Vector128<uint> x_2 = Sse2.LoadVector128(x + 8);
            Vector128<uint> x_3 = Sse2.LoadVector128(x + 12);

            ShuffleState(ref x_0, ref x_1, ref x_2, ref x_3);

            Sse2.Store(sk, Vector128.AsByte(x_0));
            Sse2.Store(sk + 16, Vector128.AsByte(x_3));
        }
    }

  [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void ShuffleState(ref Vector128<uint> x_0, ref Vector128<uint> x_1, ref Vector128<uint> x_2, ref Vector128<uint> x_3)
    {
        Vector128<uint> t_1;

        for (int i = 0; i < 20; i += 2)
        {
            x_0 = Sse2.Add(x_0, x_1);
            x_3 = Sse2.Xor(x_3, x_0);
            x_3 = Ssse3.Shuffle(x_3.AsByte(), rot16_128).AsUInt32();

            x_2 = Sse2.Add(x_2, x_3);
            x_1 = Sse2.Xor(x_1, x_2);

            t_1 = x_1;
            x_1 = Sse2.ShiftLeftLogical(x_1, 12);
            t_1 = Sse2.ShiftRightLogical(t_1, 20);
            x_1 = Sse2.Xor(x_1, t_1);

            x_0 = Sse2.Add(x_0, x_1);
            x_3 = Sse2.Xor(x_3, x_0);
            x_0 = Sse2.Shuffle(x_0, 147);
            x_3 = Ssse3.Shuffle(x_3.AsByte(), rot8_128).AsUInt32();

            x_2 = Sse2.Add(x_2, x_3);
            x_3 = Sse2.Shuffle(x_3, 78);
            x_1 = Sse2.Xor(x_1, x_2);
            x_2 = Sse2.Shuffle(x_2, 57);

            t_1 = x_1;
            x_1 = Sse2.ShiftLeftLogical(x_1, 7);
            t_1 = Sse2.ShiftRightLogical(t_1, 25);
            x_1 = Sse2.Xor(x_1, t_1);

            x_0 = Sse2.Add(x_0, x_1);
            x_3 = Sse2.Xor(x_3, x_0);
            x_3 = Ssse3.Shuffle(x_3.AsByte(), rot16_128).AsUInt32();

            x_2 = Sse2.Add(x_2, x_3);
            x_1 = Sse2.Xor(x_1, x_2);

            t_1 = x_1;
            x_1 = Sse2.ShiftLeftLogical(x_1, 12);
            t_1 = Sse2.ShiftRightLogical(t_1, 20);
            x_1 = Sse2.Xor(x_1, t_1);

            x_0 = Sse2.Add(x_0, x_1);
            x_3 = Sse2.Xor(x_3, x_0);
            x_0 = Sse2.Shuffle(x_0, 57);
            x_3 = Ssse3.Shuffle(x_3.AsByte(), rot8_128).AsUInt32();

            x_2 = Sse2.Add(x_2, x_3);
            x_3 = Sse2.Shuffle(x_3, 78);
            x_1 = Sse2.Xor(x_1, x_2);
            x_2 = Sse2.Shuffle(x_2, 147);

            t_1 = x_1;
            x_1 = Sse2.ShiftLeftLogical(x_1, 7);
            t_1 = Sse2.ShiftRightLogical(t_1, 25);
            x_1 = Sse2.Xor(x_1, t_1);
        }
    }
}
#pragma warning restore IDE0007 // Use implicit type
#endif