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
public class ChaCha20IntrinsicsBenchmark
{
    private static readonly Random Rnd = new(42);

    private Memory<byte> _key;
    private Memory<byte> _nonce;
    private Memory<byte> _message;
    private ChaCha20 _cipher;

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

        _nonce = new byte[12];
        Rnd.NextBytes(_nonce.Span);

        _message = new byte[Size];
        Rnd.NextBytes(_message.Span);

        _cipher = new ChaCha20(_key, 0);
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Scalar")]
    public void EncryptScalar()
    {
        // Disable all SIMD instructions to force scalar path
        Environment.SetEnvironmentVariable("COMPlus_EnableAVX2", "0");
        Environment.SetEnvironmentVariable("COMPlus_EnableSSE3", "0");

        var ciphertext = new byte[_message.Length];
        _cipher.Encrypt(_message.Span, _nonce.Span, ciphertext);
    }

    [Benchmark]
    [BenchmarkCategory("SSSE3")]
    public void EncryptSSSE3()
    {
        // Enable SSSE3 but disable AVX2
        Environment.SetEnvironmentVariable("COMPlus_EnableAVX2", "0");
        Environment.SetEnvironmentVariable("COMPlus_EnableSSE3", "1");

        var ciphertext = new byte[_message.Length];
        _cipher.Encrypt(_message.Span, _nonce.Span, ciphertext);
    }

    [Benchmark]
    [BenchmarkCategory("AVX2")]
    public void EncryptAVX2()
    {
        // Enable both SSSE3 and AVX2 (AVX2 will be preferred)
        Environment.SetEnvironmentVariable("COMPlus_EnableAVX2", "1");
        Environment.SetEnvironmentVariable("COMPlus_EnableSSE3", "1");

        var ciphertext = new byte[_message.Length];
        _cipher.Encrypt(_message.Span, _nonce.Span, ciphertext);
    }

    [Benchmark]
    [BenchmarkCategory("AdvSIMD")]
    public void EncryptAdvSIMD()
    {
        // Enable ARM AdvSIMD
        Environment.SetEnvironmentVariable("COMPlus_EnableAdvSimd", "1");

        var ciphertext = new byte[_message.Length];
        _cipher.Encrypt(_message.Span, _nonce.Span, ciphertext);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        // Reset environment variables
        Environment.SetEnvironmentVariable("COMPlus_EnableAVX2", null);
        Environment.SetEnvironmentVariable("COMPlus_EnableSSE3", null);
    }
}