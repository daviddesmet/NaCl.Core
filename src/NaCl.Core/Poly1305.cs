namespace NaCl.Core;

using System;
using System.Security.Cryptography;

using Internal;

/// <summary>
/// Poly1305 one-time MAC based on RFC 7539.
///
/// This is not an implementation of the MAC interface on purpose and it is not equivalent to HMAC.
/// The implementation is based on poly1305 implementation by Andrew Moon (https://github.com/floodyberry/poly1305-donna) and released as public domain.
/// </summary>
public static class Poly1305
{
    public static int MAC_TAG_SIZE_IN_BYTES = 16;
    public static int MAC_KEY_SIZE_IN_BYTES = 32;
    public const string MAC_EXCEPTION_INVALID = "Invalid MAC";

    /*
    private static long Load32(ReadOnlySpan<byte> buf, int idx)
    {
        //return ByteIntegerConverter.LoadLittleEndian32(buf, idx);
        return ((buf[idx] & 0xff)
                | ((buf[idx + 1] & 0xff) << 8)
                | ((buf[idx + 2] & 0xff) << 16)
                | ((buf[idx + 3] & 0xff) << 24))
                & 0xffffffffL;
    }

    private static long Load26(ReadOnlySpan<byte> buf, int idx, int shift) => (Load32(buf, idx) >> shift) & 0x3ffffff;

    private static void ToByteArray(byte[] output, long num, int idx)
    {
        for (var i = 0; i < 4; i++, num >>= 8)
            output[idx + i] = (byte)(num & 0xff);
    }
    */

    // private static void Fill<T>(T[] array, int start, int end, T value)
    // {
    //     /*
    //      * Shouldn't run into any exception since is not exposed to public
    //      *
    //     if (array is null)
    //         throw new ArgumentNullException(nameof(array));

    //     if (start < 0 || start >= end)
    //         throw new ArgumentOutOfRangeException(nameof(start));

    //     if (end > array.Length)
    //         throw new ArgumentOutOfRangeException(nameof(end));
    //     */

    //     for (var i = start; i < end; i++)
    //         array[i] = value;
    // }

    /*
    private static void ProcessBlock(byte[] output, ReadOnlySpan<byte> buf, int idx)
    {
        var copyCount = Math.Min(MAC_TAG_SIZE_IN_BYTES, buf.Length - idx);
        //Array.Copy(buf.ToArray(), idx, output, 0, copyCount);

        for (var i = 0; i < copyCount; i++)
            output[i] = buf[idx + i];

        output[copyCount] = 1;

        if (copyCount != MAC_TAG_SIZE_IN_BYTES)
            Fill(output, copyCount + 1, output.Length, (byte)0);
    }
    */

    private static byte[] GetLastBlock(ReadOnlySpan<byte> buf, int idx)
    {
        var output = new byte[MAC_KEY_SIZE_IN_BYTES];

        var copyCount = Math.Min(MAC_TAG_SIZE_IN_BYTES, buf.Length - idx);
        //Array.Copy(buf.ToArray(), idx, output, 0, copyCount);

        for (var i = 0; i < copyCount; i++)
            output[i] = buf[idx + i];

        output[copyCount] = 1;

        //if (copyCount != MAC_TAG_SIZE_IN_BYTES)
        //    Fill(output, copyCount + 1, output.Length, (byte)0);

        return output;
    }

    /// <summary>
    /// Computes the mac value using the specified key and data.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="data">The data.</param>
    /// <returns>System.Byte[].</returns>
    /// <exception cref="CryptographicException">The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}</exception>
    public static byte[] ComputeMac(byte[] key, byte[] data) => ComputeMac((ReadOnlySpan<byte>)key, (ReadOnlySpan<byte>)data);

    /// <summary>
    /// Computes the mac value using the specified key and data.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The input to compute the authentication tag.</param>
    /// <returns>The authentication tag.</returns>
    /// <exception cref="CryptographicException">The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}</exception>
    public static byte[] ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var mac = new byte[MAC_TAG_SIZE_IN_BYTES];
        ComputeMac(key, data, mac);
        return mac;
    }

    /// <summary>
    /// Computes the authentication <paramref name="tag"/> into a destination buffer using the specified <paramref name="key"/> and <paramref name="data"/>.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The input to compute the authentication tag.</param>
    /// <param name="tag">The byte array to receive the generated authentication tag.</param>
    /// <returns>System.Byte[].</returns>
    /// <exception cref="CryptographicException">The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}</exception>
    public static void ComputeMac(byte[] key, byte[] data, byte[] tag)
        => ComputeMac((ReadOnlySpan<byte>)key, (ReadOnlySpan<byte>)data, (Span<byte>)tag);

    /// <summary>
    /// Computes the authentication <paramref name="tag"/> into a destination buffer using the specified <paramref name="key"/> and <paramref name="data"/>.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The input to compute the authentication tag.</param>
    /// <param name="tag">The byte span to receive the generated authentication tag.</param>
    /// <returns>System.Byte[].</returns>
    /// <exception cref="CryptographicException">The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}</exception>
    public static void ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> tag)
    {
        if (key.Length != MAC_KEY_SIZE_IN_BYTES)
            throw new CryptographicException($"The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}.");

        if (tag.Length != MAC_TAG_SIZE_IN_BYTES)
            throw new CryptographicException($"The tag length in bytes must be {MAC_TAG_SIZE_IN_BYTES}.");

        // Init state
        uint h0 = 0;
        uint h1 = 0;
        uint h2 = 0;
        uint h3 = 0;
        uint h4 = 0;

        uint g0, g1, g2, g3, g4;
        uint b, nb;

        ulong tt0, tt1, tt2, tt3, tt4;
        ulong f0, f1, f2, f3;
        ulong c;

        Span<uint> internalKey = stackalloc uint[8];
        internalKey[0] = ArrayUtils.LoadUInt32LittleEndian(key, 0);
        internalKey[1] = ArrayUtils.LoadUInt32LittleEndian(key, 4);
        internalKey[2] = ArrayUtils.LoadUInt32LittleEndian(key, 8);
        internalKey[3] = ArrayUtils.LoadUInt32LittleEndian(key, 12);
        internalKey[4] = ArrayUtils.LoadUInt32LittleEndian(key, 16);
        internalKey[5] = ArrayUtils.LoadUInt32LittleEndian(key, 20);
        internalKey[6] = ArrayUtils.LoadUInt32LittleEndian(key, 24);
        internalKey[7] = ArrayUtils.LoadUInt32LittleEndian(key, 28);

        // Clamp key
        var t0 = internalKey[0];
        var t1 = internalKey[1];
        var t2 = internalKey[2];
        var t3 = internalKey[3];

        // Precompute multipliers
        var r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
        var r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
        var r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
        var r3 = t2 & 0x3f03fff; t3 >>= 8;
        var r4 = t3 & 0x00fffff;

        var s1 = r1 * 5;
        var s2 = r2 * 5;
        var s3 = r3 * 5;
        var s4 = r4 * 5;

        // Process blocks
        for (var i = 0; i < data.Length; i += MAC_TAG_SIZE_IN_BYTES)
        {
            var lastBlock = (data.Length - i) < MAC_TAG_SIZE_IN_BYTES;
            if (lastBlock)
            {
                var block = GetLastBlock(data, i); // TODO: Remove allocation

                t0 = ArrayUtils.LoadUInt32LittleEndian(block, 0);
                t1 = ArrayUtils.LoadUInt32LittleEndian(block, 4);
                t2 = ArrayUtils.LoadUInt32LittleEndian(block, 8);
                t3 = ArrayUtils.LoadUInt32LittleEndian(block, 12);

                CryptoBytes.Wipe(block);
            }
            else
            {
                t0 = ArrayUtils.LoadUInt32LittleEndian(data, i + 0);
                t1 = ArrayUtils.LoadUInt32LittleEndian(data, i + 4);
                t2 = ArrayUtils.LoadUInt32LittleEndian(data, i + 8);
                t3 = ArrayUtils.LoadUInt32LittleEndian(data, i + 12);
            }

            h0 += t0 & 0x3ffffff;
            h1 += (uint)(((((ulong)t1 << 32) | t0) >> 26) & 0x3ffffff);
            h2 += (uint)(((((ulong)t2 << 32) | t1) >> 20) & 0x3ffffff);
            h3 += (uint)(((((ulong)t3 << 32) | t2) >> 14) & 0x3ffffff);
            h4 = lastBlock ? h4 + (t3 >> 8) : h4 + ((t3 >> 8) | (1 << 24));

            // d = r * h
            tt0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
            tt1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
            tt2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
            tt3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
            tt4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

            // Partial reduction mod 2^130-5
            unchecked
            {
                h0 = (uint)tt0 & 0x3ffffff; c = (tt0 >> 26);
                tt1 += c; h1 = (uint)tt1 & 0x3ffffff; b = (uint)(tt1 >> 26);
                tt2 += b; h2 = (uint)tt2 & 0x3ffffff; b = (uint)(tt2 >> 26);
                tt3 += b; h3 = (uint)tt3 & 0x3ffffff; b = (uint)(tt3 >> 26);
                tt4 += b; h4 = (uint)tt4 & 0x3ffffff; b = (uint)(tt4 >> 26);
            }

            h0 += b * 5;
        }

        // Do final reduction mod 2^130-5
        b = h0 >> 26; h0 &= 0x3ffffff;
        h1 += b; b = h1 >> 26; h1 &= 0x3ffffff;
        h2 += b; b = h2 >> 26; h2 &= 0x3ffffff;
        h3 += b; b = h3 >> 26; h3 &= 0x3ffffff;
        h4 += b; b = h4 >> 26; h4 &= 0x3ffffff;
        h0 += b * 5;

        // Compute h - p
        g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
        g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
        g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
        g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
        g4 = unchecked(h4 + b - (1 << 26));

        // Select h if h < p, or h - p if h >= p
        b = (g4 >> 31) - 1; // mask is either 0 (h >= p) or -1 (h < p)
        nb = ~b;
        h0 = (h0 & nb) | (g0 & b);
        h1 = (h1 & nb) | (g1 & b);
        h2 = (h2 & nb) | (g2 & b);
        h3 = (h3 & nb) | (g3 & b);
        h4 = (h4 & nb) | (g4 & b);

        // h = h % (2^128)
        f0 = ((h0) | (h1 << 26)) + (ulong)internalKey[4];
        f1 = ((h1 >> 6) | (h2 << 20)) + (ulong)internalKey[5];
        f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)internalKey[6];
        f3 = ((h3 >> 18) | (h4 << 8)) + (ulong)internalKey[7];

        // mac = (h + pad) % (2^128)
        ArrayUtils.StoreUInt32LittleEndian(tag, 0, (uint)f0); f1 += (f0 >> 32);
        ArrayUtils.StoreUInt32LittleEndian(tag, 4, (uint)f1); f2 += (f1 >> 32);
        ArrayUtils.StoreUInt32LittleEndian(tag, 8, (uint)f2); f3 += (f2 >> 32);
        ArrayUtils.StoreUInt32LittleEndian(tag, 12, (uint)f3);
    }

    /// <summary>
    /// Computes the mac value using the specified key and data.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="data">The data.</param>
    /// <returns>System.Byte[].</returns>
    /// <exception cref="CryptographicException">The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}</exception>
    /*
    public static byte[] ComputeMacLegacy(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        if (key.Length != MAC_KEY_SIZE_IN_BYTES)
            throw new CryptographicException($"The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}.");

        long h0 = 0;
        long h1 = 0;
        long h2 = 0;
        long h3 = 0;
        long h4 = 0;
        long d0;
        long d1;
        long d2;
        long d3;
        long d4;
        long c;

        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        var r0 = Load26(key, 0, 0) & 0x3ffffff;
        var r1 = Load26(key, 3, 2) & 0x3ffff03;
        var r2 = Load26(key, 6, 4) & 0x3ffc0ff;
        var r3 = Load26(key, 9, 6) & 0x3f03fff;
        var r4 = Load26(key, 12, 8) & 0x00fffff;

        var s1 = r1 * 5;
        var s2 = r2 * 5;
        var s3 = r3 * 5;
        var s4 = r4 * 5;

        var buf = new byte[MAC_TAG_SIZE_IN_BYTES + 1];
        for (var i = 0; i < data.Length; i += MAC_TAG_SIZE_IN_BYTES)
        {
            ProcessBlock(buf, data, i);
            h0 += Load26(buf, 0, 0);
            h1 += Load26(buf, 3, 2);
            h2 += Load26(buf, 6, 4);
            h3 += Load26(buf, 9, 6);
            h4 += Load26(buf, 12, 8) | (buf[MAC_TAG_SIZE_IN_BYTES] << 24);

            // d = r * h
            d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
            d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
            d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
            d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

            // Partial reduction mod 2^130-5, resulting h1 might not be 26bits.
            c = d0 >> 26;
            h0 = d0 & 0x3ffffff;
            d1 += c;
            c = d1 >> 26;
            h1 = d1 & 0x3ffffff;
            d2 += c;
            c = d2 >> 26;
            h2 = d2 & 0x3ffffff;
            d3 += c;
            c = d3 >> 26;
            h3 = d3 & 0x3ffffff;
            d4 += c;
            c = d4 >> 26;
            h4 = d4 & 0x3ffffff;
            h0 += c * 5;
            c = h0 >> 26;
            h0 = h0 & 0x3ffffff;
            h1 += c;
        }
        // Do final reduction mod 2^130-5
        c = h1 >> 26;
        h1 = h1 & 0x3ffffff;
        h2 += c;
        c = h2 >> 26;
        h2 = h2 & 0x3ffffff;
        h3 += c;
        c = h3 >> 26;
        h3 = h3 & 0x3ffffff;
        h4 += c;
        c = h4 >> 26;
        h4 = h4 & 0x3ffffff;
        h0 += c * 5; // c * 5 can be at most 5
        c = h0 >> 26;
        h0 = h0 & 0x3ffffff;
        h1 += c;

        // Compute h - p
        var g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= 0x3ffffff;
        var g1 = h1 + c;
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        var g2 = h2 + c;
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        var g3 = h3 + c;
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        var g4 = h4 + c - (1 << 26);

        // Select h if h < p, or h - p if h >= p
        var mask = g4 >> 63; // mask is either 0 (h >= p) or -1 (h < p)
        h0 &= mask;
        h1 &= mask;
        h2 &= mask;
        h3 &= mask;
        h4 &= mask;
        mask = ~mask;
        h0 |= g0 & mask;
        h1 |= g1 & mask;
        h2 |= g2 & mask;
        h3 |= g3 & mask;
        h4 |= g4 & mask;

        // h = h % (2^128)
        h0 = (h0 | (h1 << 26)) & 0xffffffffL;
        h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffL;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffL;
        h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffL;

        // mac = (h + pad) % (2^128)
        c = h0 + Load32(key, 16);
        h0 = c & 0xffffffffL;
        c = h1 + Load32(key, 20) + (c >> 32);
        h1 = c & 0xffffffffL;
        c = h2 + Load32(key, 24) + (c >> 32);
        h2 = c & 0xffffffffL;
        c = h3 + Load32(key, 28) + (c >> 32);
        h3 = c & 0xffffffffL;

        var mac = new byte[MAC_TAG_SIZE_IN_BYTES];
        ToByteArray(mac, h0, 0);
        ToByteArray(mac, h1, 4);
        ToByteArray(mac, h2, 8);
        ToByteArray(mac, h3, 12);

        return mac;
    }
    */

    /// <summary>
    /// Verifies the authentication <paramref name="mac"/> using the specified <paramref name="key"/> and <paramref name="data"/>.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data.</param>
    /// <param name="tag">The authentication tag.</param>
    /// <exception cref="CryptographicException"></exception>
    public static void VerifyMac(byte[] key, byte[] data, byte[] tag) => VerifyMac((ReadOnlySpan<byte>)key, (ReadOnlySpan<byte>)data, (ReadOnlySpan<byte>)tag);

    /// <summary>
    /// Verifies the authentication <paramref name="mac"/> using the specified <paramref name="key"/> and <paramref name="data"/>.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data.</param>
    /// <param name="tag">The authentication tag.</param>
    /// <exception cref="CryptographicException"></exception>
    public static void VerifyMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> tag)
    {
        if (tag.Length != MAC_TAG_SIZE_IN_BYTES)
            throw new CryptographicException($"The tag length in bytes must be {MAC_TAG_SIZE_IN_BYTES}.");

        Span<byte> mac = stackalloc byte[MAC_TAG_SIZE_IN_BYTES];
        ComputeMac(key, data, mac);

        if (!CryptoBytes.ConstantTimeEquals(mac, tag))
            throw new CryptographicException(MAC_EXCEPTION_INVALID);
    }
}