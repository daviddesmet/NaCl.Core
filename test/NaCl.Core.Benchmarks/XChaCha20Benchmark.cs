namespace NaCl.Core.Benchmarks;

using System;
using System.Collections.Generic;

using Base;

using BenchmarkDotNet.Attributes;

[BenchmarkCategory("Stream Cipher")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
public class XChaCha20Benchmark
{
    private static readonly Random Rnd = new(42);

    private Memory<byte> _key;
    private Memory<byte> _nonce;
    private Memory<byte> _message;
    private Memory<byte> _cipherText;
    private XChaCha20 _cipher;

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

        _nonce = new byte[24];
        Rnd.NextBytes(_nonce.Span);

        _message = new byte[Size];
        Rnd.NextBytes(_message.Span);

        _cipherText = new byte[Size];

        _cipher = new XChaCha20(_key, 0);
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