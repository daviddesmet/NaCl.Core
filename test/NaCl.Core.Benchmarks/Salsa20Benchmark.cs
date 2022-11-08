namespace NaCl.Core.Benchmarks;

using System;

using Base;

using BenchmarkDotNet.Attributes;

[BenchmarkCategory("Stream Cipher")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
public class Salsa20Benchmark
{
    private static readonly Random rnd = new Random(42);

    private Memory<byte> key;
    private Memory<byte> nonce;
    private Memory<byte> message;
    private Memory<byte> cipherText;
    private Salsa20 cipher;

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

        nonce = new byte[8];
        rnd.NextBytes(nonce.Span);

        message = new byte[Size];
        rnd.NextBytes(message.Span);

        cipherText = new byte[Size];
        var c = new Salsa20(key, 0);
        c.Encrypt(message.Span, nonce.Span, cipherText.Span);

        cipher = new Salsa20(key, 0);
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
    public void Decrypt()
    {
        var plaintext = new byte[cipherText.Length];
        cipher.Decrypt(cipherText.Span, nonce.Span, plaintext);
    }

    //[Benchmark]
    //[BenchmarkCategory("Decryption")]
    //[ArgumentsSource(nameof(TestVectors))]
    //public void Decrypt(Tests.Vectors.Salsa20TestVector test)
    //{
    //    var plaintext = new byte[test.CipherText.Length];
    //    var cipher = new Salsa20(test.Key, test.InitialCounter);
    //    cipher.Decrypt(test.CipherText, test.Nonce, plaintext);
    //}

    //public IEnumerable<object> TestVectors()
    //{
    //    //foreach (var test in ParseTestVectors(GetTestVector());)
    //    //    yield return test;
    //}
}
