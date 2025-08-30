namespace NaCl.Core.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;

using Base;

[SimpleJob(RuntimeMoniker.Net90)]
[BenchmarkCategory("Hardware Intrinsics")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class Salsa20IntrinsicsBenchmark
{
    private static readonly Random Rnd = new(42);

    private Memory<byte> _key;
    private Memory<byte> _nonce;
    private Memory<byte> _message;
    private Salsa20 _cipher;

    [Params(
        (int)1E+3,  // 1 KB - small data
        (int)1E+5,  // 100 KB - medium data
        (int)1E+6)] // 1 MB - large data (most relevant for intrinsics benefits)
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
        Rnd.NextBytes(_key.Span);

        _nonce = new byte[8]; // Salsa20 uses 8-byte nonce
        Rnd.NextBytes(_nonce.Span);

        _message = new byte[Size];
        Rnd.NextBytes(_message.Span);

        _cipher = new Salsa20(_key, 0);
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Default")]
    public void EncryptDefault()
    {
        // Use default runtime detection - best available instruction set
        var ciphertext = new byte[_message.Length];
        _cipher.Encrypt(_message.Span, _nonce.Span, ciphertext);
    }

    [Benchmark]
    [BenchmarkCategory("Intrinsics")]
    public void EncryptIntrinsics()
    {
        // Test intrinsics path (same as default on modern hardware)
        var ciphertext = new byte[_message.Length];
        _cipher.Encrypt(_message.Span, _nonce.Span, ciphertext);
    }
}