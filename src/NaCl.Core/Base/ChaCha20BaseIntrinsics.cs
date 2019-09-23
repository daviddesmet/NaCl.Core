#if NETCOREAPP3_0
#pragma warning disable IDE0007 // Use implicit type
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace NaCl.Core.Base
{
    public static class ChaCha20BaseIntrinsics
    {
        private static Vector128<byte> rot8_128 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
        private static Vector128<byte> rot16_128 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
        private static Vector256<byte> rot8_256 = Vector256.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
        private static Vector256<byte> rot16_256 = Vector256.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void ChaCha20(uint* x, byte* m, byte* c, ulong bytes)
        {
            if (Avx2.IsSupported && bytes >= 512)
            {
                Vector256<uint> x_0 = Vector256.Create(x[0]);
                Vector256<uint> x_1 = Vector256.Create(x[1]);
                Vector256<uint> x_2 = Vector256.Create(x[2]);
                Vector256<uint> x_3 = Vector256.Create(x[3]);
                Vector256<uint> x_4 = Vector256.Create(x[4]);
                Vector256<uint> x_5 = Vector256.Create(x[5]);
                Vector256<uint> x_6 = Vector256.Create(x[6]);
                Vector256<uint> x_7 = Vector256.Create(x[7]);
                Vector256<uint> x_8 = Vector256.Create(x[8]);
                Vector256<uint> x_9 = Vector256.Create(x[9]);
                Vector256<uint> x_10 = Vector256.Create(x[10]);
                Vector256<uint> x_11 = Vector256.Create(x[11]);
                Vector256<uint> x_12;
                Vector256<uint> x_13;
                Vector256<uint> x_14 = Vector256.Create(x[14]);
                Vector256<uint> x_15 = Vector256.Create(x[15]);
                Vector256<uint> orig0 = x_0;
                Vector256<uint> orig1 = x_1;
                Vector256<uint> orig2 = x_2;
                Vector256<uint> orig3 = x_3;
                Vector256<uint> orig4 = x_4;
                Vector256<uint> orig5 = x_5;
                Vector256<uint> orig6 = x_6;
                Vector256<uint> orig7 = x_7;
                Vector256<uint> orig8 = x_8;
                Vector256<uint> orig9 = x_9;
                Vector256<uint> orig10 = x_10;
                Vector256<uint> orig11 = x_11;
                Vector256<uint> orig14 = x_14;
                Vector256<uint> orig15 = x_15;
                Vector256<uint> t12, t13;

                while (bytes >= 512)
                {
                    Vector256<uint> addv12 = Vector256.Create(0, 1, 2, 3).AsUInt32();
                    Vector256<uint> addv13 = Vector256.Create(4, 5, 6, 7).AsUInt32();
                    Vector256<uint> permute = Vector256.Create(0, 1, 4, 5, 2, 3, 6, 7).AsUInt32();
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
                    ulong in1213 = in12 | (ulong)in13 << 32;
                    x_12 = Avx2.BroadcastScalarToVector256(Vector128.Create(in1213, 0)).AsUInt32();
                    x_13 = x_12;
                    t12 = Avx2.Add(addv12, x_12);
                    t13 = Avx2.Add(addv13, x_13);
                    x_12 = Avx2.UnpackLow(t12, t13);
                    x_13 = Avx2.UnpackHigh(t12, t13);
                    t12 = Avx2.UnpackLow(x_12, x_13);
                    t13 = Avx2.UnpackHigh(x_12, x_13);
                    x_12 = Avx2.PermuteVar8x32(t12, permute);
                    x_13 = Avx2.PermuteVar8x32(t13, permute);
                    in1213 += 8;
                    x[12] = (uint)(in1213 & 0xFFFFFFFF);
                    x[13] = (uint)(in1213 >> 32 & 0xFFFFFFFF);
                    for (int i = 0; i < 20; i += 2)
                    {
                        Vec256Round(ref x_0, ref x_4, ref x_8, ref x_12, ref x_1, ref x_5, ref x_9, ref x_13, ref x_2, ref x_6, ref x_10, ref x_14, ref x_3, ref x_7, ref x_11, ref x_15);
                        Vec256Round(ref x_0, ref x_5, ref x_10, ref x_15, ref x_1, ref x_6, ref x_11, ref x_12, ref x_2, ref x_7, ref x_8, ref x_13, ref x_3, ref x_4, ref x_9, ref x_14);
                    }

                    Vector256<uint> t_0, t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9, t_10, t_11, t_12, t_13, t_14, t_15;
                    // ONEOCTO enter
                    // ONEQUAD_UNPCK enter
                    x_0 = Avx2.Add(x_0, orig0);
                    x_1 = Avx2.Add(x_1, orig1);
                    x_2 = Avx2.Add(x_2, orig2);
                    x_3 = Avx2.Add(x_3, orig3);
                    t_0 = Avx2.UnpackLow(x_0, x_1);
                    t_1 = Avx2.UnpackLow(x_2, x_3);
                    t_2 = Avx2.UnpackHigh(x_0, x_1);
                    t_3 = Avx2.UnpackHigh(x_2, x_3);
                    x_0 = Avx2.UnpackLow(t_0, t_1);
                    x_1 = Avx2.UnpackHigh(t_0, t_1);
                    x_2 = Avx2.UnpackLow(t_2, t_3);
                    x_3 = Avx2.UnpackHigh(t_2, t_3);
                    // ONEQUAD_UNPCK exit
                    // ONEQUAD_UNPCK enter
                    x_4 = Avx2.Add(x_4, orig0);
                    x_5 = Avx2.Add(x_5, orig1);
                    x_6 = Avx2.Add(x_6, orig2);
                    x_7 = Avx2.Add(x_7, orig3);
                    t_0 = Avx2.UnpackLow(x_4, x_5);
                    t_1 = Avx2.UnpackLow(x_6, x_7);
                    t_2 = Avx2.UnpackHigh(x_4, x_5);
                    t_3 = Avx2.UnpackHigh(x_6, x_7);
                    x_4 = Avx2.UnpackLow(t_0, t_1);
                    x_5 = Avx2.UnpackHigh(t_0, t_1);
                    x_6 = Avx2.UnpackLow(t_2, t_3);
                    x_7 = Avx2.UnpackHigh(t_2, t_3);
                    // ONEQUAD_UNPCK exit
                    t_0 = Avx2.Permute2x128(x_0, x_4, 32);
                    t_4 = Avx2.Permute2x128(x_0, x_4, 49);
                    t_1 = Avx2.Permute2x128(x_1, x_5, 32);
                    t_5 = Avx2.Permute2x128(x_1, x_5, 49);
                    t_2 = Avx2.Permute2x128(x_2, x_6, 32);
                    t_6 = Avx2.Permute2x128(x_2, x_6, 49);
                    t_3 = Avx2.Permute2x128(x_3, x_7, 32);
                    t_7 = Avx2.Permute2x128(x_3, x_7, 49);
                    t_0 = Avx2.Xor(t_0, Avx.LoadVector256(m).AsUInt32<byte>());
                    t_1 = Avx2.Xor(t_1, Avx.LoadVector256(m + 64).AsUInt32<byte>());
                    t_2 = Avx2.Xor(t_2, Avx.LoadVector256(m + 128).AsUInt32<byte>());
                    t_3 = Avx2.Xor(t_3, Avx.LoadVector256(m + 192).AsUInt32<byte>());
                    t_4 = Avx2.Xor(t_4, Avx.LoadVector256(m + 256).AsUInt32<byte>());
                    t_5 = Avx2.Xor(t_5, Avx.LoadVector256(m + 320).AsUInt32<byte>());
                    t_6 = Avx2.Xor(t_6, Avx.LoadVector256(m + 384).AsUInt32<byte>());
                    t_7 = Avx2.Xor(t_7, Avx.LoadVector256(m + 448).AsUInt32<byte>());
                    Avx.Store(c, t_0.AsByte<uint>());
                    Avx.Store(c + 64, t_1.AsByte<uint>());
                    Avx.Store(c + 128, t_2.AsByte<uint>());
                    Avx.Store(c + 192, t_3.AsByte<uint>());
                    Avx.Store(c + 256, t_4.AsByte<uint>());
                    Avx.Store(c + 320, t_5.AsByte<uint>());
                    Avx.Store(c + 384, t_6.AsByte<uint>());
                    Avx.Store(c + 448, t_7.AsByte<uint>());
                    // ONEOCTO exit

                    m += 32;
                    c += 32;

                    // ONEOCTO enter
                    // ONEQUAD_UNPCK enter
                    x_8 = Avx2.Add(x_8, orig8);
                    x_9 = Avx2.Add(x_9, orig9);
                    x_10 = Avx2.Add(x_10, orig10);
                    x_11 = Avx2.Add(x_11, orig11);
                    t_8 = Avx2.UnpackLow(x_8, x_9);
                    t_9 = Avx2.UnpackLow(x_10, x_11);
                    t_10 = Avx2.UnpackHigh(x_8, x_9);
                    t_11 = Avx2.UnpackHigh(x_10, x_11);
                    x_8 = Avx2.UnpackLow(t_8, t_9);
                    x_9 = Avx2.UnpackHigh(t_8, t_9);
                    x_10 = Avx2.UnpackLow(t_10, t_11);
                    x_11 = Avx2.UnpackHigh(t_10, t_11);
                    // ONEQUAD_UNPCK exit
                    // ONEQUAD_UNPCK enter
                    x_12 = Avx2.Add(x_12, orig8);
                    x_13 = Avx2.Add(x_13, orig9);
                    x_14 = Avx2.Add(x_14, orig10);
                    x_15 = Avx2.Add(x_15, orig11);
                    t_8 = Avx2.UnpackLow(x_12, x_13);
                    t_9 = Avx2.UnpackLow(x_14, x_15);
                    t_10 = Avx2.UnpackHigh(x_12, x_13);
                    t_11 = Avx2.UnpackHigh(x_14, x_15);
                    x_12 = Avx2.UnpackLow(t_8, t_9);
                    x_13 = Avx2.UnpackHigh(t_8, t_9);
                    x_14 = Avx2.UnpackLow(t_10, t_11);
                    x_15 = Avx2.UnpackHigh(t_10, t_11);
                    // ONEQUAD_UNPCK exit
                    // ONEQUAD_UNPCK enter
                    t_8 = Avx2.Permute2x128(x_8, x_12, 32);
                    t_12 = Avx2.Permute2x128(x_8, x_12, 49);
                    t_9 = Avx2.Permute2x128(x_9, x_13, 32);
                    t_13 = Avx2.Permute2x128(x_9, x_13, 49);
                    t_10 = Avx2.Permute2x128(x_10, x_14, 32);
                    t_14 = Avx2.Permute2x128(x_10, x_14, 49);
                    t_11 = Avx2.Permute2x128(x_11, x_15, 32);
                    t_15 = Avx2.Permute2x128(x_11, x_15, 49);
                    t_8 = Avx2.Xor(t_8, Avx.LoadVector256(m).AsUInt32());
                    t_9 = Avx2.Xor(t_9, Avx.LoadVector256(m + 64).AsUInt32());
                    t_10 = Avx2.Xor(t_10, Avx.LoadVector256(m + 128).AsUInt32());
                    t_11 = Avx2.Xor(t_11, Avx.LoadVector256(m + 192).AsUInt32());
                    t_12 = Avx2.Xor(t_12, Avx.LoadVector256(m + 256).AsUInt32());
                    t_13 = Avx2.Xor(t_13, Avx.LoadVector256(m + 320).AsUInt32());
                    t_14 = Avx2.Xor(t_14, Avx.LoadVector256(m + 384).AsUInt32());
                    t_15 = Avx2.Xor(t_15, Avx.LoadVector256(m + 448).AsUInt32());
                    Avx.Store(c, t_8.AsByte());
                    Avx.Store(c + 64, t_9.AsByte());
                    Avx.Store(c + 128, t_10.AsByte());
                    Avx.Store(c + 192, t_11.AsByte());
                    Avx.Store(c + 256, t_12.AsByte());
                    Avx.Store(c + 320, t_13.AsByte());
                    Avx.Store(c + 384, t_14.AsByte());
                    Avx.Store(c + 448, t_15.AsByte());
                    // ONEOCTO exit
                    m -= 32;
                    c -= 32;
                    bytes -= (long)512;
                    c += 512;
                    m += 512;
                }
            }
            if (bytes >= 256)
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
            while (bytes >= 64)
            {
                Vector128<uint> x_0 = Sse2.LoadVector128(x);
                Vector128<uint> x_1 = Sse2.LoadVector128(x + 4);
                Vector128<uint> x_2 = Sse2.LoadVector128(x + 8);
                Vector128<uint> x_3 = Sse2.LoadVector128(x + 12);
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
                x_0 = Sse2.Add(x_0, Sse2.LoadVector128(x));
                x_1 = Sse2.Add(x_1, Sse2.LoadVector128(x + 4));
                x_2 = Sse2.Add(x_2, Sse2.LoadVector128(x + 8));
                x_3 = Sse2.Add(x_3, Sse2.LoadVector128(x + 12));
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
            if (bytes > 0)
            {
                Vector128<uint> x_0 = Sse2.LoadVector128(x);
                Vector128<uint> x_1 = Sse2.LoadVector128(x + 4);
                Vector128<uint> x_2 = Sse2.LoadVector128(x + 8);
                Vector128<uint> x_3 = Sse2.LoadVector128(x + 12);
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
                    x_0 = Sse2.Shuffle(x_0, 0x93);
                    x_3 = Ssse3.Shuffle(x_3.AsByte(), rot8_128).AsUInt32();

                    x_2 = Sse2.Add(x_2, x_3);
                    x_3 = Sse2.Shuffle(x_3, 0x4e);
                    x_1 = Sse2.Xor(x_1, x_2);
                    x_2 = Sse2.Shuffle(x_2, 0x39);

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
                    x_0 = Sse2.Shuffle(x_0, 0x39);
                    x_3 = Ssse3.Shuffle(x_3.AsByte(), rot8_128).AsUInt32();

                    x_2 = Sse2.Add(x_2, x_3);
                    x_3 = Sse2.Shuffle(x_3, 0x4e);
                    x_1 = Sse2.Xor(x_1, x_2);
                    x_2 = Sse2.Shuffle(x_2, 0x93);

                    t_1 = x_1;
                    x_1 = Sse2.ShiftLeftLogical(x_1, 7);
                    t_1 = Sse2.ShiftRightLogical(t_1, 25);
                    x_1 = Sse2.Xor(x_1, t_1);
                }
                x_0 = Sse2.Add(x_0, Sse2.LoadVector128(x));
                x_1 = Sse2.Add(x_1, Sse2.LoadVector128(x + 4));
                x_2 = Sse2.Add(x_2, Sse2.LoadVector128(x + 8));
                x_3 = Sse2.Add(x_3, Sse2.LoadVector128(x + 12));
                byte* partialblock = stackalloc byte[64];
                Sse2.Store(partialblock, Vector128.AsByte(x_0));
                Sse2.Store(partialblock + 16, Vector128.AsByte(x_1));
                Sse2.Store(partialblock + 32, Vector128.AsByte(x_2));
                Sse2.Store(partialblock + 48, Vector128.AsByte(x_3));

                for (ulong i = 0; i < bytes; i++)
                {
                    c[i] = (byte)(m[i] ^ partialblock[i]);
                }
                for (int n = 0; n < 64 / sizeof(int); n++)
                {
                    ((int*)partialblock)[n] = 0;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void OneQuad(ref Vector128<uint> x_A, ref Vector128<uint> x_B, ref Vector128<uint> x_C, ref Vector128<uint> x_D, ref Vector128<uint> origA, ref Vector128<uint> origB, ref Vector128<uint> origC, ref Vector128<uint> origD, byte* m, byte* c)
        {
            x_A = Sse2.Add(x_A, origA);
            x_B = Sse2.Add(x_B, origB);
            x_C = Sse2.Add(x_C, origC);
            x_D = Sse2.Add(x_D, origD);
            Vector128<uint> vector128 = Sse2.UnpackLow(x_A, x_B);
            Vector128<uint> vector1281 = Sse2.UnpackLow(x_C, x_D);
            Vector128<uint> vector1282 = Sse2.UnpackHigh(x_A, x_B);
            Vector128<uint> vector1283 = Sse2.UnpackHigh(x_C, x_D);
            x_A = Vector128.AsUInt32<ulong>(Sse2.UnpackLow(Vector128.AsUInt64<uint>(vector128), Vector128.AsUInt64<uint>(vector1281)));
            x_B = Vector128.AsUInt32<ulong>(Sse2.UnpackHigh(Vector128.AsUInt64<uint>(vector128), Vector128.AsUInt64<uint>(vector1281)));
            x_C = Vector128.AsUInt32<ulong>(Sse2.UnpackLow(Vector128.AsUInt64<uint>(vector1282), Vector128.AsUInt64<uint>(vector1283)));
            x_D = Vector128.AsUInt32<ulong>(Sse2.UnpackHigh(Vector128.AsUInt64<uint>(vector1282), Vector128.AsUInt64<uint>(vector1283)));
            Vector128<uint> vector1284 = Vector128.AsUInt32<byte>(Sse2.Xor(Vector128.AsByte<uint>(x_A), Sse2.LoadVector128(m)));
            Sse2.Store(c, Vector128.AsByte<uint>(vector1284));
            Vector128<uint> vector1285 = Vector128.AsUInt32<byte>(Sse2.Xor(Vector128.AsByte<uint>(x_B), Sse2.LoadVector128(m + 64)));
            Sse2.Store(c + 64, Vector128.AsByte<uint>(vector1285));
            Vector128<uint> vector1286 = Vector128.AsUInt32<byte>(Sse2.Xor(Vector128.AsByte<uint>(x_C), Sse2.LoadVector128(m + 128)));
            Sse2.Store(c + 128, Vector128.AsByte<uint>(vector1286));
            Vector128<uint> vector1287 = Vector128.AsUInt32<byte>(Sse2.Xor(Vector128.AsByte<uint>(x_D), Sse2.LoadVector128(m + 192)));
            Sse2.Store(c + 192, Vector128.AsByte<uint>(vector1287));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Vec128QuarterRound(ref Vector128<uint> x_A, ref Vector128<uint> x_B, ref Vector128<uint> x_C, ref Vector128<uint> x_D)
        {
            x_A = Sse2.Add(x_A, x_B);
            Vector128<uint> vector128 = Sse2.Xor(x_D, x_A);
            x_D = Vector128.AsUInt32<byte>(Ssse3.Shuffle(Vector128.AsByte<uint>(vector128), rot16_128));
            x_C = Sse2.Add(x_C, x_D);
            Vector128<uint> vector1281 = Sse2.Xor(x_B, x_C);
            x_B = Sse2.Or(Sse2.ShiftLeftLogical(vector1281, 12), Sse2.ShiftRightLogical(vector1281, 20));
            x_A = Sse2.Add(x_A, x_B);
            vector128 = Sse2.Xor(x_D, x_A);
            x_D = Vector128.AsUInt32<byte>(Ssse3.Shuffle(Vector128.AsByte<uint>(vector128), rot8_128));
            x_C = Sse2.Add(x_C, x_D);
            vector1281 = Sse2.Xor(x_B, x_C);
            x_B = Sse2.Or(Sse2.ShiftLeftLogical(vector1281, 7), Sse2.ShiftRightLogical(vector1281, 25));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Vec256Round(ref Vector256<uint> A1, ref Vector256<uint> B1, ref Vector256<uint> C1, ref Vector256<uint> D1, ref Vector256<uint> A2, ref Vector256<uint> B2, ref Vector256<uint> C2, ref Vector256<uint> D2, ref Vector256<uint> A3, ref Vector256<uint> B3, ref Vector256<uint> C3, ref Vector256<uint> D3, ref Vector256<uint> A4, ref Vector256<uint> B4, ref Vector256<uint> C4, ref Vector256<uint> D4)
        {
            Vector256Line1(ref A1, ref B1, ref C1, ref D1);
            Vector256Line1(ref A2, ref B2, ref C2, ref D2);
            Vector256Line1(ref A3, ref B3, ref C3, ref D3);
            Vector256Line1(ref A4, ref B4, ref C4, ref D4);
            Vector256Line2(ref A1, ref B1, ref C1, ref D1);
            Vector256Line2(ref A2, ref B2, ref C2, ref D2);
            Vector256Line2(ref A3, ref B3, ref C3, ref D3);
            Vector256Line2(ref A4, ref B4, ref C4, ref D4);
            Vector256Line3(ref A1, ref B1, ref C1, ref D1);
            Vector256Line3(ref A2, ref B2, ref C2, ref D2);
            Vector256Line3(ref A3, ref B3, ref C3, ref D3);
            Vector256Line3(ref A4, ref B4, ref C4, ref D4);
            Vector256Line4(ref A1, ref B1, ref C1, ref D1);
            Vector256Line4(ref A2, ref B2, ref C2, ref D2);
            Vector256Line4(ref A3, ref B3, ref C3, ref D3);
            Vector256Line4(ref A4, ref B4, ref C4, ref D4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Vector256Line1(ref Vector256<uint> x_A, ref Vector256<uint> x_B, ref Vector256<uint> x_C, ref Vector256<uint> x_D)
        {
            x_A = Avx2.Add(x_A, x_B);
            x_D = Avx2.Shuffle(Avx2.Xor(x_D, x_A).AsByte<uint>(), rot16_256).AsUInt32<byte>();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Vector256Line2(ref Vector256<uint> x_A, ref Vector256<uint> x_B, ref Vector256<uint> x_C, ref Vector256<uint> x_D)
        {
            x_C = Avx2.Add(x_C, x_D);
            Vector256<uint> vector256 = Avx2.Xor(x_B, x_C);
            x_B = Avx2.Or(Avx2.ShiftLeftLogical(vector256, 12), Avx2.ShiftRightLogical(vector256, 20));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Vector256Line3(ref Vector256<uint> x_A, ref Vector256<uint> x_B, ref Vector256<uint> x_C, ref Vector256<uint> x_D)
        {
            x_A = Avx2.Add(x_A, x_B);
            x_D = Avx2.Shuffle(Avx2.Xor(x_D, x_A).AsByte<uint>(), rot8_256).AsUInt32<byte>();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Vector256Line4(ref Vector256<uint> x_A, ref Vector256<uint> x_B, ref Vector256<uint> x_C, ref Vector256<uint> x_D)
        {
            x_C = Avx2.Add(x_C, x_D);
            Vector256<uint> temp = Avx2.Xor(x_B, x_C);
            x_B = Avx2.Or(Avx2.ShiftLeftLogical(temp, 7), Avx2.ShiftRightLogical(temp, 25));
        }
    }
}
#pragma warning restore IDE0007 // Use implicit type
#endif