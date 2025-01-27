namespace NaCl.Core.Benchmarks;

using System;
using System.Collections.Generic;

using Base;

using BenchmarkDotNet.Attributes;

[BenchmarkCategory("Stream Cipher")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
public class ChaCha20Benchmark
{
    private static readonly Random Rnd = new(42);

    private Memory<byte> _key;
    private Memory<byte> _nonce;
    private Memory<byte> _message;
    private Memory<byte> _cipherText;
    private ChaCha20 _cipher;

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
        _key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
        Rnd.NextBytes(_key.Span);

        _nonce = new byte[12];
        Rnd.NextBytes(_nonce.Span);

        _message = new byte[Size];
        Rnd.NextBytes(_message.Span);

        _cipher = new ChaCha20(_key, 0);
    }

    [Benchmark]
    [BenchmarkCategory("Encryption")]
    public void Encrypt()
    {
        _cipherText = new byte[_message.Length];
        _cipher.Encrypt(_message.Span, _nonce.Span, _cipherText.Span);
    }

    [Benchmark]
    [BenchmarkCategory("Decryption")]
    [ArgumentsSource(nameof(TestVectors))]
    public void Decrypt(Tests.Vectors.Rfc8439TestVector test)
    {
        var plaintext = new byte[test.CipherText.Length];
        var cipher = new ChaCha20(test.Key, test.InitialCounter);
        cipher.Decrypt(test.CipherText, test.Nonce, plaintext);
    }

    public IEnumerable<object> TestVectors()
    {
        //foreach (var test in Tests.Rfc8439TestVector.Rfc8439TestVectors)
        //    yield return test;

        yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[0];
        yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[1];
        yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[2];
        yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[3];
        yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[4];
        yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[5];
        yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[6];
        yield return Tests.Vectors.Rfc8439TestVector.Rfc8439TestVectors[7];
    }

    // TODO: Use the encrypt value (from Encrypt method) to benchmark decryption
    //[Benchmark]
    //[BenchmarkCategory("Decryption")]
    //public byte[] Decrypt(byte[] ciphertext) => cipher.Decrypt(ciphertext);
}