#if INTRINSICS
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System;

namespace NaCl.Core.Base.SalsaIntrinsics;

#pragma warning disable IDE0007 // Use implicit type
internal static class Salsa64
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Process64(uint* x, ref byte* m, ref byte* c, ref ulong bytes)
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

        // Xor the key stream and message to obtain the cipher.
        x_0 = Sse2.Xor(x_0.AsByte(), Sse2.LoadVector128(m)).AsUInt32();
        x_1 = Sse2.Xor(x_1.AsByte(), Sse2.LoadVector128(m + 16)).AsUInt32();
        x_2 = Sse2.Xor(x_2.AsByte(), Sse2.LoadVector128(m + 32)).AsUInt32();
        x_3 = Sse2.Xor(x_3.AsByte(), Sse2.LoadVector128(m + 48)).AsUInt32();

        Sse2.Store(c, x_0.AsByte());
        Sse2.Store(c + 16, x_1.AsByte());
        Sse2.Store(c + 32, x_2.AsByte());
        Sse2.Store(c + 48, x_3.AsByte());

        // Increment 64 bit counter for the original state.
        uint in8 = x[8];
        uint in9 = x[9];
        in8++;
        if (in8 == 0)
        {
            in9++;
        }
        x[8] = in8;
        x[9] = in9;

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

        // TODO use vector<T>
        for (ulong i = 0; i < bytes; i++)
        {
            c[i] = (byte)(m[i] ^ partialblock[i]);
        }
        for (int n = 0; n < 64 / sizeof(int); n++)
        {
            ((int*)partialblock)[n] = 0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void HSalsa20(ReadOnlySpan<uint> state, Span<byte> subKey)
    {
        fixed (uint* x = state)
        fixed (byte* sk = subKey)
        {
            Vector128<uint> x_0 = Sse2.LoadVector128(x);
            Vector128<uint> x_1 = Sse2.LoadVector128(x + 4);
            Vector128<uint> x_2 = Sse2.LoadVector128(x + 8);
            Vector128<uint> x_3 = Sse2.LoadVector128(x + 12);

            ShuffleState(ref x_0, ref x_1, ref x_2, ref x_3);

            // <0, 5, 2, 3> + <8, 9, 10, 15> -> <0, 5, 10, 15>
            Vector128<uint> t_0 = Avx2.Blend(x_0, x_1, 0b_00_00_00_10);
            Vector128<uint> t_1 = Avx2.Blend(x_2, x_3, 0b_00_00_10_00);
            Vector128<uint> t_2 = Avx2.Blend(t_0, t_1, 0b_00_00_11_00);

            // Get <8, 9, 6, 7> then shuffle to <6, 7, 8, 9>
            Vector128<uint> t_3 = Avx2.Blend(x_1, x_2, 0b_00_00_00_11);
            t_3 = Sse2.Shuffle(t_3, 0b_01_00_11_10);

            Sse2.Store(sk, Vector128.AsByte(t_2));
            Sse2.Store(sk + 16, Vector128.AsByte(t_3));
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void KeyStream64(ReadOnlySpan<uint> state, Span<byte> output)
    {
        fixed (byte* k = output)
        fixed (uint* x = state)
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

            Sse2.Store(k, x_0.AsByte());
            Sse2.Store(k + 16, x_1.AsByte());
            Sse2.Store(k + 32, x_2.AsByte());
            Sse2.Store(k + 48, x_3.AsByte());
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void ShuffleState(ref Vector128<uint> x_0, ref Vector128<uint> x_1, ref Vector128<uint> x_2, ref Vector128<uint> x_3)
    {
        Transpose(ref x_0, ref x_1, ref x_2, ref x_3);

        // Diagonalize
        x_1 = Sse2.Shuffle(x_1, 0b_00_11_10_01);
        x_2 = Sse2.Shuffle(x_2, 0b_01_00_11_10);
        x_3 = Sse2.Shuffle(x_3, 0b_10_01_00_11);

        Transpose(ref x_0, ref x_1, ref x_2, ref x_3);

        for (int i = 0; i < 20; i += 2)
        {
            x_1 = Sse2.Xor(x_1, Vector128Rotate(Sse2.Add(x_0, x_3), 7));
            x_2 = Sse2.Xor(x_2, Vector128Rotate(Sse2.Add(x_1, x_0), 9));
            x_3 = Sse2.Xor(x_3, Vector128Rotate(Sse2.Add(x_2, x_1), 13));
            x_0 = Sse2.Xor(x_0, Vector128Rotate(Sse2.Add(x_3, x_2), 18));

            x_1 = Sse2.Shuffle(x_1, 0b_10_01_00_11);
            x_2 = Sse2.Shuffle(x_2, 0b_01_00_11_10);
            x_3 = Sse2.Shuffle(x_3, 0b_00_11_10_01);

            x_3 = Sse2.Xor(x_3, Vector128Rotate(Sse2.Add(x_0, x_1), 7));
            x_2 = Sse2.Xor(x_2, Vector128Rotate(Sse2.Add(x_3, x_0), 9));
            x_1 = Sse2.Xor(x_1, Vector128Rotate(Sse2.Add(x_2, x_3), 13));
            x_0 = Sse2.Xor(x_0, Vector128Rotate(Sse2.Add(x_1, x_2), 18));

            x_1 = Sse2.Shuffle(x_1, 0b_00_11_10_01);
            x_2 = Sse2.Shuffle(x_2, 0b_01_00_11_10);
            x_3 = Sse2.Shuffle(x_3, 0b_10_01_00_11);
        }

        Transpose(ref x_0, ref x_1, ref x_2, ref x_3);

        // Diagonalize
        x_1 = Sse2.Shuffle(x_1, 0b_10_01_00_11);
        x_2 = Sse2.Shuffle(x_2, 0b_01_00_11_10);
        x_3 = Sse2.Shuffle(x_3, 0b_00_11_10_01);

        Transpose(ref x_0, ref x_1, ref x_2, ref x_3);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> Vector128Rotate(Vector128<uint> a, byte imm) => Sse2.Or(Sse2.ShiftLeftLogical(a, imm), Sse2.ShiftRightLogical(a, (byte)(32 - imm)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Transpose(ref Vector128<uint> a, ref Vector128<uint> b, ref Vector128<uint> c, ref Vector128<uint> d)
    {
        var w_0 = Sse2.UnpackLow(a, b).AsUInt64();
        var w_1 = Sse2.UnpackHigh(a, b).AsUInt64();
        var w_2 = Sse2.UnpackLow(c, d).AsUInt64();
        var w_3 = Sse2.UnpackHigh(c, d).AsUInt64();

        a = Sse2.UnpackLow(w_0, w_2).AsUInt32();
        b = Sse2.UnpackHigh(w_0, w_2).AsUInt32();
        c = Sse2.UnpackLow(w_1, w_3).AsUInt32();
        d = Sse2.UnpackHigh(w_1, w_3).AsUInt32();
    }
}
#pragma warning restore IDE0007 // Use implicit type
#endif