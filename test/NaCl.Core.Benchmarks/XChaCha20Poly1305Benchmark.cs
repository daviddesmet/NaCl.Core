namespace NaCl.Core.Benchmarks;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

using NaCl.Core.Base;

using BenchmarkDotNet.Attributes;

[BenchmarkCategory("AEAD")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
public class XChaCha20Poly1305Benchmark
{
    private static readonly Random Rnd = new(42);

    private Memory<byte> _key;
    private Memory<byte> _nonce;
    private Memory<byte> _message;
    private Memory<byte> _tag;
    private Memory<byte> _aad;
    private Memory<byte> _ciphertext;

    private XChaCha20Poly1305 _aead;

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
        RandomNumberGenerator.Fill(_key.Span);

        _nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
        RandomNumberGenerator.Fill(_nonce.Span);

        _tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];

        _message = new byte[Size];
        Rnd.NextBytes(_message.Span);

        _aad = new byte[24];
        Rnd.NextBytes(_aad.Span);

        _ciphertext = new byte[_message.Length];

        _aead = new XChaCha20Poly1305(_key);
    }

    [Benchmark]
    [BenchmarkCategory("Encryption")]
    public void Encrypt() => _aead.Encrypt(_nonce.Span, _message.Span, _ciphertext.Span, _tag.Span, _aad.Span);

    [Benchmark]
    [BenchmarkCategory("Decryption")]
    [ArgumentsSource(nameof(TestVectors))]
    public void Decrypt(Tests.Vectors.XChaCha20Poly1305TestVector test)
    {
        var aead = new XChaCha20Poly1305(test.Key);
        var plaintext = new byte[test.CipherText.Length];
        aead.Decrypt(test.Nonce, test.CipherText, test.Tag, plaintext, test.Aad);
    }

    public static IEnumerable<object> TestVectors()
    {
        //foreach (var test in Tests.Rfc8439TestVector.Rfc7634AeadTestVectors)
        //    yield return test;

        yield return Tests.Vectors.XChaCha20Poly1305TestVector.TestVectors[0];
        yield return Tests.Vectors.XChaCha20Poly1305TestVector.TestVectors[1];
        yield return Tests.Vectors.XChaCha20Poly1305TestVector.TestVectors[2];
    }

    // TODO: Use the encrypt value (from Encrypt method) to benchmark decryption
    //[Benchmark]
    //[BenchmarkCategory("Decryption")]
    //public byte[] Decrypt(byte[] ciphertext) => aead.Decrypt(ciphertext, aad);
}