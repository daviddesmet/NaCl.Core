namespace NaCl.Core;

using System;
using System.Security.Cryptography;
#if NET6_0_OR_GREATER
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics.Arm;
#endif

using Internal;

/// <summary>
/// Poly1305 one-time MAC based on RFC 7539.
///
/// This is not an implementation of the MAC interface on purpose and it is not equivalent to HMAC.
/// The implementation is based on poly1305 implementation by Andrew Moon (https://github.com/floodyberry/poly1305-donna) and released as public domain.
/// </summary>
public static class Poly1305
{
    public const int MAC_TAG_SIZE_IN_BYTES = 16;
    public const int MAC_KEY_SIZE_IN_BYTES = 32;
    public const string MAC_EXCEPTION_INVALID = "Invalid MAC";

    private static void GetLastBlock(ReadOnlySpan<byte> buf, int idx, Span<byte> output)
    {
        var copyCount = Math.Min(MAC_TAG_SIZE_IN_BYTES, buf.Length - idx);

        // Clear the output buffer first (ensure padding is zero)
        output.Clear();

        // Copy the remaining data
        for (var i = 0; i < copyCount; i++)
            output[i] = buf[idx + i];

        // Add the padding bit
        output[copyCount] = 1;
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
#if NET6_0_OR_GREATER
        if (Avx2.IsSupported)
        {
            ComputeMacAvx2(key, data, tag);
            return;
        }
        if (Sse2.IsSupported)
        {
            ComputeMacSse2(key, data, tag);
            return;
        }
        if (AdvSimd.IsSupported)
        {
            ComputeMacAdvSimd(key, data, tag);
            return;
        }
#endif
        ComputeMacScalar(key, data, tag);
    }

    /// <summary>
    /// Computes the authentication <paramref name="tag"/> into a destination buffer using the specified <paramref name="key"/> and <paramref name="data"/> using scalar operations.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The input to compute the authentication tag.</param>
    /// <param name="tag">The byte span to receive the generated authentication tag.</param>
    /// <returns>System.Byte[].</returns>
    /// <exception cref="CryptographicException">The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}</exception>
    private static void ComputeMacScalar(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> tag)
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
        Span<byte> block = stackalloc byte[MAC_KEY_SIZE_IN_BYTES]; // Move stackalloc out of loop
        for (var i = 0; i < data.Length; i += MAC_TAG_SIZE_IN_BYTES)
        {
            var lastBlock = (data.Length - i) < MAC_TAG_SIZE_IN_BYTES;
            if (lastBlock)
            {
                GetLastBlock(data, i, block);

                t0 = ArrayUtils.LoadUInt32LittleEndian(block, 0);
                t1 = ArrayUtils.LoadUInt32LittleEndian(block, 4);
                t2 = ArrayUtils.LoadUInt32LittleEndian(block, 8);
                t3 = ArrayUtils.LoadUInt32LittleEndian(block, 12);

                block.Clear(); // Clear sensitive data
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

#if NET6_0_OR_GREATER
    /// <summary>
    /// Computes the authentication <paramref name="tag"/> using AVX2 intrinsics.
    /// </summary>
    private static void ComputeMacAvx2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> tag)
    {
        if (key.Length != MAC_KEY_SIZE_IN_BYTES)
            throw new CryptographicException($"The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}.");

        if (tag.Length != MAC_TAG_SIZE_IN_BYTES)
            throw new CryptographicException($"The tag length in bytes must be {MAC_TAG_SIZE_IN_BYTES}.");

        // Load and clamp key using SIMD
        var keyVec = Vector256.Create(
            ArrayUtils.LoadUInt32LittleEndian(key, 0),
            ArrayUtils.LoadUInt32LittleEndian(key, 4),
            ArrayUtils.LoadUInt32LittleEndian(key, 8),
            ArrayUtils.LoadUInt32LittleEndian(key, 12),
            ArrayUtils.LoadUInt32LittleEndian(key, 16),
            ArrayUtils.LoadUInt32LittleEndian(key, 20),
            ArrayUtils.LoadUInt32LittleEndian(key, 24),
            ArrayUtils.LoadUInt32LittleEndian(key, 28)
        );

        // Extract and clamp r values
        var t0 = keyVec.GetElement(0);
        var t1 = keyVec.GetElement(1);
        var t2 = keyVec.GetElement(2);
        var t3 = keyVec.GetElement(3);

        var r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
        var r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
        var r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
        var r3 = t2 & 0x3f03fff; t3 >>= 8;
        var r4 = t3 & 0x00fffff;

        // Precompute s values and create vectors for parallel operations
        var rVec = Vector256.Create(r0, r1, r2, r3, r4, 0u, 0u, 0u);
        var sVec = Vector256.Create(r1 * 5, r2 * 5, r3 * 5, r4 * 5, 0u, 0u, 0u, 0u);

        // Initialize state
        var hVec = Vector256<uint>.Zero; // h0, h1, h2, h3, h4

        // Process data blocks
        Span<byte> block = stackalloc byte[MAC_KEY_SIZE_IN_BYTES]; // Move stackalloc out of loop
        for (var i = 0; i < data.Length; i += MAC_TAG_SIZE_IN_BYTES)
        {
            var lastBlock = (data.Length - i) < MAC_TAG_SIZE_IN_BYTES;
            Vector256<uint> blockVec;

            if (lastBlock)
            {
                GetLastBlock(data, i, block);
                blockVec = Vector256.Create(
                    ArrayUtils.LoadUInt32LittleEndian(block, 0),
                    ArrayUtils.LoadUInt32LittleEndian(block, 4),
                    ArrayUtils.LoadUInt32LittleEndian(block, 8),
                    ArrayUtils.LoadUInt32LittleEndian(block, 12),
                    0u, 0u, 0u, 0u
                );
                block.Clear(); // Clear sensitive data
            }
            else
            {
                blockVec = Vector256.Create(
                    ArrayUtils.LoadUInt32LittleEndian(data, i + 0),
                    ArrayUtils.LoadUInt32LittleEndian(data, i + 4),
                    ArrayUtils.LoadUInt32LittleEndian(data, i + 8),
                    ArrayUtils.LoadUInt32LittleEndian(data, i + 12),
                    0u, 0u, 0u, 0u
                );
            }

            // Extract values and perform polynomial operations
            // This is a simplified version - the full vectorization would be more complex
            // Due to the interdependent nature of Poly1305's field arithmetic
            ComputeBlockScalar(ref hVec, blockVec, rVec, sVec, lastBlock);
        }

        // Final reduction and output (scalar for now)
        FinalizeTagAvx2(hVec, keyVec, tag);
    }

    private static void ComputeBlockScalar(ref Vector256<uint> hVec, Vector256<uint> blockVec, Vector256<uint> rVec, Vector256<uint> sVec, bool lastBlock)
    {
        // Extract current hash state
        var h0 = hVec.GetElement(0);
        var h1 = hVec.GetElement(1);
        var h2 = hVec.GetElement(2);
        var h3 = hVec.GetElement(3);
        var h4 = hVec.GetElement(4);

        // Extract block values
        var t0 = blockVec.GetElement(0);
        var t1 = blockVec.GetElement(1);
        var t2 = blockVec.GetElement(2);
        var t3 = blockVec.GetElement(3);

        // Extract r and s values
        var r0 = rVec.GetElement(0);
        var r1 = rVec.GetElement(1);
        var r2 = rVec.GetElement(2);
        var r3 = rVec.GetElement(3);
        var r4 = rVec.GetElement(4);
        var s1 = sVec.GetElement(0);
        var s2 = sVec.GetElement(1);
        var s3 = sVec.GetElement(2);
        var s4 = sVec.GetElement(3);

        // Add block to accumulator
        h0 += t0 & 0x3ffffff;
        h1 += (uint)(((((ulong)t1 << 32) | t0) >> 26) & 0x3ffffff);
        h2 += (uint)(((((ulong)t2 << 32) | t1) >> 20) & 0x3ffffff);
        h3 += (uint)(((((ulong)t3 << 32) | t2) >> 14) & 0x3ffffff);
        h4 = lastBlock ? h4 + (t3 >> 8) : h4 + ((t3 >> 8) | (1u << 24));

        // Polynomial multiplication d = r * h
        var tt0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
        var tt1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
        var tt2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
        var tt3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
        var tt4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

        // Partial reduction mod 2^130-5
        unchecked
        {
            h0 = (uint)tt0 & 0x3ffffff; var c = (tt0 >> 26);
            tt1 += c; h1 = (uint)tt1 & 0x3ffffff; var b = (uint)(tt1 >> 26);
            tt2 += b; h2 = (uint)tt2 & 0x3ffffff; b = (uint)(tt2 >> 26);
            tt3 += b; h3 = (uint)tt3 & 0x3ffffff; b = (uint)(tt3 >> 26);
            tt4 += b; h4 = (uint)tt4 & 0x3ffffff; b = (uint)(tt4 >> 26);
            h0 += b * 5;
        }

        // Update hash vector
        hVec = Vector256.Create(h0, h1, h2, h3, h4, 0u, 0u, 0u);
    }

    private static void FinalizeTagAvx2(Vector256<uint> hVec, Vector256<uint> keyVec, Span<byte> tag)
    {
        // Extract final hash state
        var h0 = hVec.GetElement(0);
        var h1 = hVec.GetElement(1);
        var h2 = hVec.GetElement(2);
        var h3 = hVec.GetElement(3);
        var h4 = hVec.GetElement(4);

        // Final reduction mod 2^130-5
        var b = h0 >> 26; h0 &= 0x3ffffff;
        h1 += b; b = h1 >> 26; h1 &= 0x3ffffff;
        h2 += b; b = h2 >> 26; h2 &= 0x3ffffff;
        h3 += b; b = h3 >> 26; h3 &= 0x3ffffff;
        h4 += b; b = h4 >> 26; h4 &= 0x3ffffff;
        h0 += b * 5;

        // Compute h - p
        var g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
        var g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
        var g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
        var g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
        var g4 = unchecked(h4 + b - (1u << 26));

        // Select h if h < p, or h - p if h >= p
        b = (g4 >> 31) - 1;
        var nb = ~b;
        h0 = (h0 & nb) | (g0 & b);
        h1 = (h1 & nb) | (g1 & b);
        h2 = (h2 & nb) | (g2 & b);
        h3 = (h3 & nb) | (g3 & b);
        h4 = (h4 & nb) | (g4 & b);

        // h = h % (2^128)
        var f0 = ((h0) | (h1 << 26)) + (ulong)keyVec.GetElement(4);
        var f1 = ((h1 >> 6) | (h2 << 20)) + (ulong)keyVec.GetElement(5);
        var f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)keyVec.GetElement(6);
        var f3 = ((h3 >> 18) | (h4 << 8)) + (ulong)keyVec.GetElement(7);

        // mac = (h + pad) % (2^128)
        ArrayUtils.StoreUInt32LittleEndian(tag, 0, (uint)f0); f1 += (f0 >> 32);
        ArrayUtils.StoreUInt32LittleEndian(tag, 4, (uint)f1); f2 += (f1 >> 32);
        ArrayUtils.StoreUInt32LittleEndian(tag, 8, (uint)f2); f3 += (f2 >> 32);
        ArrayUtils.StoreUInt32LittleEndian(tag, 12, (uint)f3);
    }

    /// <summary>
    /// Computes the authentication <paramref name="tag"/> using SSE2 intrinsics.
    /// Uses SIMD for data loading and final operations while maintaining scalar polynomial arithmetic.
    /// </summary>
    private static unsafe void ComputeMacSse2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> tag)
    {
        if (key.Length != MAC_KEY_SIZE_IN_BYTES)
            throw new CryptographicException($"The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}.");

        if (tag.Length != MAC_TAG_SIZE_IN_BYTES)
            throw new CryptographicException($"The tag length in bytes must be {MAC_TAG_SIZE_IN_BYTES}.");

        // Load key using SIMD
        fixed (byte* keyPtr = key)
        {
            var keyLo = Sse2.LoadVector128((uint*)keyPtr);       // First 16 bytes (r)
            var keyHi = Sse2.LoadVector128((uint*)(keyPtr + 16)); // Last 16 bytes (s/pad)

            // Extract and clamp r values
            var t0 = keyLo.GetElement(0);
            var t1 = keyLo.GetElement(1);
            var t2 = keyLo.GetElement(2);
            var t3 = keyLo.GetElement(3);

            var r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
            var r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
            var r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
            var r3 = t2 & 0x3f03fff; t3 >>= 8;
            var r4 = t3 & 0x00fffff;

            var s1 = r1 * 5;
            var s2 = r2 * 5;
            var s3 = r3 * 5;
            var s4 = r4 * 5;

            // Initialize hash state
            uint h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

            // Process data blocks
            Span<byte> block = stackalloc byte[MAC_KEY_SIZE_IN_BYTES];
            fixed (byte* dataPtr = data)
            fixed (byte* blockPtr = block)
            {
                for (var i = 0; i < data.Length; i += MAC_TAG_SIZE_IN_BYTES)
                {
                    var lastBlock = (data.Length - i) < MAC_TAG_SIZE_IN_BYTES;
                    Vector128<uint> dataVec;

                    if (lastBlock)
                    {
                        GetLastBlock(data, i, block);
                        dataVec = Sse2.LoadVector128((uint*)blockPtr);
                        block.Clear();
                    }
                    else
                    {
                        // Use SIMD load for aligned/unaligned data
                        dataVec = Sse2.LoadVector128((uint*)(dataPtr + i));
                    }

                    // Extract block values from vector
                    t0 = dataVec.GetElement(0);
                    t1 = dataVec.GetElement(1);
                    t2 = dataVec.GetElement(2);
                    t3 = dataVec.GetElement(3);

                    // Add block to accumulator
                    h0 += t0 & 0x3ffffff;
                    h1 += (uint)(((((ulong)t1 << 32) | t0) >> 26) & 0x3ffffff);
                    h2 += (uint)(((((ulong)t2 << 32) | t1) >> 20) & 0x3ffffff);
                    h3 += (uint)(((((ulong)t3 << 32) | t2) >> 14) & 0x3ffffff);
                    h4 = lastBlock ? h4 + (t3 >> 8) : h4 + ((t3 >> 8) | (1u << 24));

                    // Polynomial multiplication d = r * h
                    var tt0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
                    var tt1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
                    var tt2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
                    var tt3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
                    var tt4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

                    // Partial reduction mod 2^130-5
                    unchecked
                    {
                        h0 = (uint)tt0 & 0x3ffffff; var c = (tt0 >> 26);
                        tt1 += c; h1 = (uint)tt1 & 0x3ffffff; var b = (uint)(tt1 >> 26);
                        tt2 += b; h2 = (uint)tt2 & 0x3ffffff; b = (uint)(tt2 >> 26);
                        tt3 += b; h3 = (uint)tt3 & 0x3ffffff; b = (uint)(tt3 >> 26);
                        tt4 += b; h4 = (uint)tt4 & 0x3ffffff; b = (uint)(tt4 >> 26);
                        h0 += b * 5;
                    }
                }
            }

            // Finalize using SIMD for final operations
            FinalizeTagSse2(h0, h1, h2, h3, h4, keyHi, tag);
        }
    }

    private static unsafe void FinalizeTagSse2(uint h0, uint h1, uint h2, uint h3, uint h4, Vector128<uint> padVec, Span<byte> tag)
    {
        // Final reduction mod 2^130-5
        var b = h0 >> 26; h0 &= 0x3ffffff;
        h1 += b; b = h1 >> 26; h1 &= 0x3ffffff;
        h2 += b; b = h2 >> 26; h2 &= 0x3ffffff;
        h3 += b; b = h3 >> 26; h3 &= 0x3ffffff;
        h4 += b; b = h4 >> 26; h4 &= 0x3ffffff;
        h0 += b * 5;

        // Compute h - p
        var g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
        var g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
        var g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
        var g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
        var g4 = unchecked(h4 + b - (1u << 26));

        // Select h if h < p, or h - p if h >= p
        b = (g4 >> 31) - 1;
        var nb = ~b;
        h0 = (h0 & nb) | (g0 & b);
        h1 = (h1 & nb) | (g1 & b);
        h2 = (h2 & nb) | (g2 & b);
        h3 = (h3 & nb) | (g3 & b);
        h4 = (h4 & nb) | (g4 & b);

        // h = h % (2^128) + pad
        var f0 = ((h0) | (h1 << 26)) + (ulong)padVec.GetElement(0);
        var f1 = ((h1 >> 6) | (h2 << 20)) + (ulong)padVec.GetElement(1);
        var f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)padVec.GetElement(2);
        var f3 = ((h3 >> 18) | (h4 << 8)) + (ulong)padVec.GetElement(3);

        // Propagate carries and store using SIMD
        f1 += (f0 >> 32);
        f2 += (f1 >> 32);
        f3 += (f2 >> 32);

        var result = Vector128.Create((uint)f0, (uint)f1, (uint)f2, (uint)f3);
        fixed (byte* tagPtr = tag)
        {
            Sse2.Store((uint*)tagPtr, result);
        }
    }

    /// <summary>
    /// Computes the authentication <paramref name="tag"/> using ARM AdvSIMD intrinsics.
    /// Uses SIMD for data loading and final operations while maintaining scalar polynomial arithmetic.
    /// </summary>
    private static unsafe void ComputeMacAdvSimd(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> tag)
    {
        if (key.Length != MAC_KEY_SIZE_IN_BYTES)
            throw new CryptographicException($"The key length in bytes must be {MAC_KEY_SIZE_IN_BYTES}.");

        if (tag.Length != MAC_TAG_SIZE_IN_BYTES)
            throw new CryptographicException($"The tag length in bytes must be {MAC_TAG_SIZE_IN_BYTES}.");

        // Load key using SIMD
        fixed (byte* keyPtr = key)
        {
            var keyLo = AdvSimd.LoadVector128((uint*)keyPtr);       // First 16 bytes (r)
            var keyHi = AdvSimd.LoadVector128((uint*)(keyPtr + 16)); // Last 16 bytes (s/pad)

            // Extract and clamp r values
            var t0 = keyLo.GetElement(0);
            var t1 = keyLo.GetElement(1);
            var t2 = keyLo.GetElement(2);
            var t3 = keyLo.GetElement(3);

            var r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
            var r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
            var r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
            var r3 = t2 & 0x3f03fff; t3 >>= 8;
            var r4 = t3 & 0x00fffff;

            var s1 = r1 * 5;
            var s2 = r2 * 5;
            var s3 = r3 * 5;
            var s4 = r4 * 5;

            // Initialize hash state
            uint h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

            // Process data blocks
            Span<byte> block = stackalloc byte[MAC_KEY_SIZE_IN_BYTES];
            fixed (byte* dataPtr = data)
            fixed (byte* blockPtr = block)
            {
                for (var i = 0; i < data.Length; i += MAC_TAG_SIZE_IN_BYTES)
                {
                    var lastBlock = (data.Length - i) < MAC_TAG_SIZE_IN_BYTES;
                    Vector128<uint> dataVec;

                    if (lastBlock)
                    {
                        GetLastBlock(data, i, block);
                        dataVec = AdvSimd.LoadVector128((uint*)blockPtr);
                        block.Clear();
                    }
                    else
                    {
                        // Use SIMD load for data
                        dataVec = AdvSimd.LoadVector128((uint*)(dataPtr + i));
                    }

                    // Extract block values from vector
                    t0 = dataVec.GetElement(0);
                    t1 = dataVec.GetElement(1);
                    t2 = dataVec.GetElement(2);
                    t3 = dataVec.GetElement(3);

                    // Add block to accumulator
                    h0 += t0 & 0x3ffffff;
                    h1 += (uint)(((((ulong)t1 << 32) | t0) >> 26) & 0x3ffffff);
                    h2 += (uint)(((((ulong)t2 << 32) | t1) >> 20) & 0x3ffffff);
                    h3 += (uint)(((((ulong)t3 << 32) | t2) >> 14) & 0x3ffffff);
                    h4 = lastBlock ? h4 + (t3 >> 8) : h4 + ((t3 >> 8) | (1u << 24));

                    // Polynomial multiplication d = r * h
                    var tt0 = (ulong)h0 * r0 + (ulong)h1 * s4 + (ulong)h2 * s3 + (ulong)h3 * s2 + (ulong)h4 * s1;
                    var tt1 = (ulong)h0 * r1 + (ulong)h1 * r0 + (ulong)h2 * s4 + (ulong)h3 * s3 + (ulong)h4 * s2;
                    var tt2 = (ulong)h0 * r2 + (ulong)h1 * r1 + (ulong)h2 * r0 + (ulong)h3 * s4 + (ulong)h4 * s3;
                    var tt3 = (ulong)h0 * r3 + (ulong)h1 * r2 + (ulong)h2 * r1 + (ulong)h3 * r0 + (ulong)h4 * s4;
                    var tt4 = (ulong)h0 * r4 + (ulong)h1 * r3 + (ulong)h2 * r2 + (ulong)h3 * r1 + (ulong)h4 * r0;

                    // Partial reduction mod 2^130-5
                    unchecked
                    {
                        h0 = (uint)tt0 & 0x3ffffff; var c = (tt0 >> 26);
                        tt1 += c; h1 = (uint)tt1 & 0x3ffffff; var b = (uint)(tt1 >> 26);
                        tt2 += b; h2 = (uint)tt2 & 0x3ffffff; b = (uint)(tt2 >> 26);
                        tt3 += b; h3 = (uint)tt3 & 0x3ffffff; b = (uint)(tt3 >> 26);
                        tt4 += b; h4 = (uint)tt4 & 0x3ffffff; b = (uint)(tt4 >> 26);
                        h0 += b * 5;
                    }
                }
            }

            // Finalize using SIMD for final operations
            FinalizeTagAdvSimd(h0, h1, h2, h3, h4, keyHi, tag);
        }
    }

    private static unsafe void FinalizeTagAdvSimd(uint h0, uint h1, uint h2, uint h3, uint h4, Vector128<uint> padVec, Span<byte> tag)
    {
        // Final reduction mod 2^130-5
        var b = h0 >> 26; h0 &= 0x3ffffff;
        h1 += b; b = h1 >> 26; h1 &= 0x3ffffff;
        h2 += b; b = h2 >> 26; h2 &= 0x3ffffff;
        h3 += b; b = h3 >> 26; h3 &= 0x3ffffff;
        h4 += b; b = h4 >> 26; h4 &= 0x3ffffff;
        h0 += b * 5;

        // Compute h - p
        var g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
        var g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
        var g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
        var g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
        var g4 = unchecked(h4 + b - (1u << 26));

        // Select h if h < p, or h - p if h >= p
        b = (g4 >> 31) - 1;
        var nb = ~b;
        h0 = (h0 & nb) | (g0 & b);
        h1 = (h1 & nb) | (g1 & b);
        h2 = (h2 & nb) | (g2 & b);
        h3 = (h3 & nb) | (g3 & b);
        h4 = (h4 & nb) | (g4 & b);

        // h = h % (2^128) + pad
        var f0 = ((h0) | (h1 << 26)) + (ulong)padVec.GetElement(0);
        var f1 = ((h1 >> 6) | (h2 << 20)) + (ulong)padVec.GetElement(1);
        var f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)padVec.GetElement(2);
        var f3 = ((h3 >> 18) | (h4 << 8)) + (ulong)padVec.GetElement(3);

        // Propagate carries and store using SIMD
        f1 += (f0 >> 32);
        f2 += (f1 >> 32);
        f3 += (f2 >> 32);

        var result = Vector128.Create((uint)f0, (uint)f1, (uint)f2, (uint)f3);
        fixed (byte* tagPtr = tag)
        {
            AdvSimd.Store((uint*)tagPtr, result);
        }
    }
#endif

    /// <summary>
    /// Verifies the authentication tag using the specified <paramref name="key"/> and <paramref name="data"/>.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data.</param>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <exception cref="CryptographicException">Thrown when the key length is invalid, tag length is invalid, or the tag verification fails.</exception>
    public static void VerifyMac(byte[] key, byte[] data, byte[] tag) => VerifyMac((ReadOnlySpan<byte>)key, (ReadOnlySpan<byte>)data, (ReadOnlySpan<byte>)tag);

    /// <summary>
    /// Verifies the authentication tag using the specified <paramref name="key"/> and <paramref name="data"/>.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="data">The data.</param>
    /// <param name="tag">The authentication tag to verify.</param>
    /// <exception cref="CryptographicException">Thrown when the key length is invalid, tag length is invalid, or the tag verification fails.</exception>
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