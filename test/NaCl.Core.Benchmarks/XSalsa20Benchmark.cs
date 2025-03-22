﻿namespace NaCl.Core.Benchmarks;

using System;
using Base;
using BenchmarkDotNet.Attributes;

[BenchmarkCategory("Stream Cipher")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
public class XSalsa20Benchmark
{
    private static readonly Random Rnd = new(42);

    private Memory<byte> _key;
    private Memory<byte> _nonce;
    private Memory<byte> _message;
    private Memory<byte> _cipherText;
    private XSalsa20 _cipher;

    [Params(
        (int)1E+2,  // 100 bytes
        (int)1E+3,  // 1 000 bytes = 1 KB
        (int)1E+5  // 100 000 bytes = 100 KB
        )] // 10 000 000 bytes = 10 MB
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
        var c = new XSalsa20(_key, 0);
        c.Encrypt(_message.Span, _nonce.Span, _cipherText.Span);

        _cipher = new XSalsa20(_key, 0);
    }

    [Benchmark]
    [BenchmarkCategory("Encryption")]
    public void Encrypt()
    {
        var ciphertext = new byte[_message.Length];
        _cipher.Encrypt(_message.Span, _nonce.Span, ciphertext);
    }

    [Benchmark]
    [BenchmarkCategory("Decryption")]
    public void Decrypt()
    {
        var plaintext = new byte[_cipherText.Length];
        _cipher.Decrypt(_cipherText.Span, _nonce.Span, plaintext);
    }

    //[Benchmark]
    //[BenchmarkCategory("Decryption")]
    //[ArgumentsSource(nameof(TestVectors))]
    //public void Decrypt(Tests.Vectors.Rfc8439TestVector test)
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