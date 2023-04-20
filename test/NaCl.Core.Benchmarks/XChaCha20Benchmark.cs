namespace NaCl.Core.Benchmarks;

using System;
using System.Collections.Generic;
using System.Linq;

using Base;
using Internal;

using BenchmarkDotNet.Attributes;

[BenchmarkCategory("Stream Cipher")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
public class XChaCha20Benchmark
{
    private static readonly Random rnd = new Random(42);

    private Memory<byte> key;
    private Memory<byte> nonce;
    private Memory<byte> message;
    private XChaCha20 cipher;

    [Params(
        (int)1E+2,  // 100 bytes
        (int)1E+3,  // 1 000 bytes = 1 KB
        (int)1E+4,  // 10 000 bytes = 10 KB
        (int)1E+5,  // 100 000 bytes = 100 KB
        (int)1E+6,  // 1 000 000 bytes = 1 MB
        (int)1E+7)] // 10 000 000 bytes = 10 MB
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
        rnd.NextBytes(key.Span);

        nonce = new byte[24];
        rnd.NextBytes(nonce.Span);

        message = new byte[Size];
        rnd.NextBytes(message.Span);

        cipher = new XChaCha20(key, 0);
    }

    [Benchmark]
    [BenchmarkCategory("Encryption")]
    public void Encrypt()
    {
        var ciphertext = new byte[message.Length];
        cipher.Encrypt(message.Span, nonce.Span, ciphertext);
    }

    [Benchmark]
    [BenchmarkCategory("Decryption")]
    [ArgumentsSource(nameof(TestVectors))]
    public void Decrypt(Tests.Vectors.XChaCha20TestVector test)
    {
        var plaintext = new byte[test.CipherText.Length];
        var cipher = new XChaCha20(test.Key, 0);
        cipher.Decrypt(test.CipherText, test.Nonce, plaintext);
    }

    public IEnumerable<object> TestVectors()
    {
        //foreach (var test in Tests.XChaCha20TestVector.XChaCha20TestVectors)
        //    yield return test;

        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[0];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[1];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[2];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[3];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[4];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[5];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[6];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[7];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[8];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[9];
        yield return Tests.Vectors.XChaCha20TestVector.XChaCha20TestVectors[10];
    }

    // TODO: Use the encrypt value (from Encrypt method) to benchmark decryption
    //[Benchmark]
    //[BenchmarkCategory("Decryption")]
    //public byte[] Decrypt(byte[] ciphertext) => cipher.Decrypt(ciphertext);
}