#if INTRINSICS
namespace NaCl.Core.Base.SalsaIntrinsics;

using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

#pragma warning disable IDE0007 // Use implicit type
internal static class Salsa256
{
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
        Vector128<uint> x_8;
        Vector128<uint> x_9;
        Vector128<uint> x_10 = Vector128.Create(x[10]);
        Vector128<uint> x_11 = Vector128.Create(x[11]);
        Vector128<uint> x_12 = Vector128.Create(x[12]);
        Vector128<uint> x_13 = Vector128.Create(x[13]);
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
        Vector128<uint> orig8;
        Vector128<uint> orig9;
        Vector128<uint> orig10 = x_10;
        Vector128<uint> orig11 = x_11;
        Vector128<uint> orig12 = x_12;
        Vector128<uint> orig13 = x_13;
        Vector128<uint> orig14 = x_14;
        Vector128<uint> orig15 = x_15;
        Vector128<uint> t8, t9;

        while (bytes >= 256)
        {
            Vector128<uint> addv8 = Vector128.Create(0, 1).AsUInt32();
            Vector128<uint> addv9 = Vector128.Create(2, 3).AsUInt32();

            x_0 = orig0;
            x_1 = orig1;
            x_2 = orig2;
            x_3 = orig3;
            x_4 = orig4;
            x_5 = orig5;
            x_6 = orig6;
            x_7 = orig7;
            x_10 = orig10;
            x_11 = orig11;
            x_12 = orig12;
            x_13 = orig13;
            x_14 = orig14;
            x_15 = orig15;

            uint in8 = x[8];
            uint in9 = x[9];
            ulong in89 = in8 | ((ulong)in9) << 32;
            t8 = Vector128.Create(in89).AsUInt32();
            t9 = Vector128.Create(in89).AsUInt32();

            x_8 = Sse2.Add(Vector128.AsUInt64<uint>(addv8), Vector128.AsUInt64<uint>(t8)).AsUInt32();
            x_9 = Sse2.Add(Vector128.AsUInt64<uint>(addv9), Vector128.AsUInt64<uint>(t9)).AsUInt32();

            t8 = Sse2.UnpackLow(x_8, x_9);
            t9 = Sse2.UnpackHigh(x_8, x_9);

            x_8 = Sse2.UnpackLow(t8, t9);
            x_9 = Sse2.UnpackHigh(t8, t9);

            orig8 = x_8;
            orig9 = x_9;

            in89 += 4;

            x[8] = (uint)(in89 & 0xFFFFFFFF);
            x[9] = (uint)(in89 >> 32 & 0xFFFFFFFF);

            for (int i = 0; i < 20; i += 2)
            {
                Vec128QuarterRound(ref x_0, ref x_4, ref x_8, ref x_12);
                Vec128QuarterRound(ref x_5, ref x_9, ref x_13, ref x_1);
                Vec128QuarterRound(ref x_10, ref x_14, ref x_2, ref x_6);
                Vec128QuarterRound(ref x_15, ref x_3, ref x_7, ref x_11);

                Vec128QuarterRound(ref x_0, ref x_1, ref x_2, ref x_3);
                Vec128QuarterRound(ref x_5, ref x_6, ref x_7, ref x_4);
                Vec128QuarterRound(ref x_10, ref x_11, ref x_8, ref x_9);
                Vec128QuarterRound(ref x_15, ref x_12, ref x_13, ref x_14);
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> Vector128Rotate(Vector128<uint> a, byte imm) => Sse2.Or(Sse2.ShiftLeftLogical(a, imm), Sse2.ShiftRightLogical(a, (byte)(32 - imm)));

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
        x_B = Sse2.Xor(x_B, Vector128Rotate(Sse2.Add(x_A, x_D), 7));
        x_C = Sse2.Xor(x_C, Vector128Rotate(Sse2.Add(x_B, x_A), 9));
        x_D = Sse2.Xor(x_D, Vector128Rotate(Sse2.Add(x_C, x_B), 13));
        x_A = Sse2.Xor(x_A, Vector128Rotate(Sse2.Add(x_D, x_C), 18));
    }
}
#pragma warning restore IDE0007 // Use implicit type
#endif