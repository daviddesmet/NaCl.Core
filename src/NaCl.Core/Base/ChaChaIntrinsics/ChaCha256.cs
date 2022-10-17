#if INTRINSICS
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

namespace NaCl.Core.Base.ChaChaIntrinsics;

#pragma warning disable IDE0007 // Use implicit type
internal static class ChaCha256
{
    private static readonly Vector128<byte> rot8_128 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
    private static readonly Vector128<byte> rot16_128 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Process(uint* x, ref byte* m, ref byte* c, ref ulong bytes)
    {
        Vector128<uint> x_0 = Vector128.Create(x[0]);
        Vector128<uint> x_1 = Vector128.Create(x[1]);
        Vector128<uint> x_2 = Vector128.Create(x[2]);
        Vector128<uint> x_3 = Vector128.Create(x[3]);
        Vector128<uint> x_4 = Vector128.Create(x[4]);
        Vector128<uint> x_5 = Vector128.Create(x[5]);
        Vector128<uint> x_6 = Vector128.Create(x[6]);
        Vector128<uint> x_7 = Vector128.Create(x[7]);
        Vector128<uint> x_8 = Vector128.Create(x[8]);
        Vector128<uint> x_9 = Vector128.Create(x[9]);
        Vector128<uint> x_10 = Vector128.Create(x[10]);
        Vector128<uint> x_11 = Vector128.Create(x[11]);
        Vector128<uint> x_12;
        Vector128<uint> x_13;
        Vector128<uint> x_14 = Vector128.Create(x[14]);
        Vector128<uint> x_15 = Vector128.Create(x[15]);
        Vector128<uint> orig0 = x_0;
        Vector128<uint> orig1 = x_1;
        Vector128<uint> orig2 = x_2;
        Vector128<uint> orig3 = x_3;
        Vector128<uint> orig4 = x_4;
        Vector128<uint> orig5 = x_5;
        Vector128<uint> orig6 = x_6;
        Vector128<uint> orig7 = x_7;
        Vector128<uint> orig8 = x_8;
        Vector128<uint> orig9 = x_9;
        Vector128<uint> orig10 = x_10;
        Vector128<uint> orig11 = x_11;
        Vector128<uint> orig12;
        Vector128<uint> orig13;
        Vector128<uint> orig14 = x_14;
        Vector128<uint> orig15 = x_15;
        Vector128<uint> t12, t13;

        while (bytes >= 256)
        {
            Vector128<uint> addv12 = Vector128.Create(0, 1).AsUInt32();
            Vector128<uint> addv13 = Vector128.Create(2, 3).AsUInt32();

            x_0 = orig0;
            x_1 = orig1;
            x_2 = orig2;
            x_3 = orig3;
            x_4 = orig4;
            x_5 = orig5;
            x_6 = orig6;
            x_7 = orig7;
            x_8 = orig8;
            x_9 = orig9;
            x_10 = orig10;
            x_11 = orig11;
            x_14 = orig14;
            x_15 = orig15;

            uint in12 = x[12];
            uint in13 = x[13];
            ulong in1213 = in12 | ((ulong)in13) << 32;
            t12 = Vector128.Create(in1213).AsUInt32();
            t13 = Vector128.Create(in1213).AsUInt32();

            x_12 = Sse2.Add(Vector128.AsUInt64<uint>(addv12), Vector128.AsUInt64<uint>(t12)).AsUInt32();
            x_13 = Sse2.Add(Vector128.AsUInt64<uint>(addv13), Vector128.AsUInt64<uint>(t13)).AsUInt32();

            t12 = Sse2.UnpackLow(x_12, x_13);
            t13 = Sse2.UnpackHigh(x_12, x_13);

            x_12 = Sse2.UnpackLow(t12, t13);
            x_13 = Sse2.UnpackHigh(t12, t13);

            orig12 = x_12;
            orig13 = x_13;

            in1213 += 4;

            x[12] = (uint)(in1213 & 0xFFFFFFFF);
            x[13] = (uint)(in1213 >> 32 & 0xFFFFFFFF);

            for (int i = 0; i < 20; i += 2)
            {
                Vec128QuarterRound(ref x_0, ref x_4, ref x_8, ref x_12);
                Vec128QuarterRound(ref x_1, ref x_5, ref x_9, ref x_13);
                Vec128QuarterRound(ref x_2, ref x_6, ref x_10, ref x_14);
                Vec128QuarterRound(ref x_3, ref x_7, ref x_11, ref x_15);

                Vec128QuarterRound(ref x_0, ref x_5, ref x_10, ref x_15);
                Vec128QuarterRound(ref x_1, ref x_6, ref x_11, ref x_12);
                Vec128QuarterRound(ref x_2, ref x_7, ref x_8, ref x_13);
                Vec128QuarterRound(ref x_3, ref x_4, ref x_9, ref x_14);
            }

            OneQuad(ref x_0, ref x_1, ref x_2, ref x_3, ref orig0, ref orig1, ref orig2, ref orig3, m, c);
            m += 16;
            c += 16;
            OneQuad(ref x_4, ref x_5, ref x_6, ref x_7, ref orig4, ref orig5, ref orig6, ref orig7, m, c);
            m += 16;
            c += 16;
            OneQuad(ref x_8, ref x_9, ref x_10, ref x_11, ref orig8, ref orig9, ref orig10, ref orig11, m, c);
            m += 16;
            c += 16;
            OneQuad(ref x_12, ref x_13, ref x_14, ref x_15, ref orig12, ref orig13, ref orig14, ref orig15, m, c);
            m -= 48;
            c -= 48;
            bytes -= 256;
            c += 256;
            m += 256;
        }
    }

    // 256 byte methods
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void OneQuad(ref Vector128<uint> x_A, ref Vector128<uint> x_B, ref Vector128<uint> x_C, ref Vector128<uint> x_D, ref Vector128<uint> origA, ref Vector128<uint> origB, ref Vector128<uint> origC, ref Vector128<uint> origD, byte* m, byte* c)
    {
        Vector128<uint> t_A, t_B, t_C, t_D, t0, t1, t2, t3;
        x_A = Sse2.Add(x_A, origA);
        x_B = Sse2.Add(x_B, origB);
        x_C = Sse2.Add(x_C, origC);
        x_D = Sse2.Add(x_D, origD);

        t_A = Sse2.UnpackLow(x_A, x_B);
        t_B = Sse2.UnpackLow(x_C, x_D);
        t_C = Sse2.UnpackHigh(x_A, x_B);
        t_D = Sse2.UnpackHigh(x_C, x_D);

        x_A = Sse2.UnpackLow(t_A.AsUInt64(), t_B.AsUInt64()).AsUInt32();
        x_B = Sse2.UnpackHigh(t_A.AsUInt64(), t_B.AsUInt64()).AsUInt32();
        x_C = Sse2.UnpackLow(t_C.AsUInt64(), t_D.AsUInt64()).AsUInt32();
        x_D = Sse2.UnpackHigh(t_C.AsUInt64(), t_D.AsUInt64()).AsUInt32();

        t0 = Sse2.Xor(x_A.AsByte(), Sse2.LoadVector128(m)).AsUInt32();
        Sse2.Store(c, t0.AsByte());
        t1 = Sse2.Xor(x_B.AsByte(), Sse2.LoadVector128(m + 64)).AsUInt32();
        Sse2.Store(c + 64, t1.AsByte());
        t2 = Sse2.Xor(x_C.AsByte(), Sse2.LoadVector128(m + 128)).AsUInt32();
        Sse2.Store(c + 128, t2.AsByte());
        t3 = Sse2.Xor(x_D.AsByte(), Sse2.LoadVector128(m + 192)).AsUInt32();
        Sse2.Store(c + 192, t3.AsByte());
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Vec128QuarterRound(ref Vector128<uint> x_A, ref Vector128<uint> x_B, ref Vector128<uint> x_C, ref Vector128<uint> x_D)
    {
        Vector128<uint> t_A, t_C;
        x_A = Sse2.Add(x_A, x_B);
        t_A = Sse2.Xor(x_D, x_A);
        x_D = Ssse3.Shuffle(t_A.AsByte(), rot16_128).AsUInt32();
        x_C = Sse2.Add(x_C, x_D);
        t_C = Sse2.Xor(x_B, x_C);
        x_B = Sse2.Or(Sse2.ShiftLeftLogical(t_C, 12), Sse2.ShiftRightLogical(t_C, 20));
        x_A = Sse2.Add(x_A, x_B);
        t_A = Sse2.Xor(x_D, x_A);
        x_D = Ssse3.Shuffle(t_A.AsByte(), rot8_128).AsUInt32();
        x_C = Sse2.Add(x_C, x_D);
        t_C = Sse2.Xor(x_B, x_C);
        x_B = Sse2.Or(Sse2.ShiftLeftLogical(t_C, 7), Sse2.ShiftRightLogical(t_C, 25));
    }
}
#pragma warning restore IDE0007 // Use implicit type
#endif