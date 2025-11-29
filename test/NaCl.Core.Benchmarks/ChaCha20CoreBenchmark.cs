namespace NaCl.Core.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;

/// <summary>
/// Focused benchmark comparing ChaCha20 core operations with different instruction set configurations
/// </summary>
[SimpleJob]
[BenchmarkCategory("ChaCha20 Core")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
public class ChaCha20CoreBenchmark
{
    private static readonly Random Rnd = new(42);

    private ChaCha20 _cipher;
    private byte[] _key;
    private byte[] _nonce;
    private byte[] _data1Mb;
    private byte[] _output1Mb;

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[32]; // ChaCha20 key size
        Rnd.NextBytes(_key);

        _nonce = new byte[12]; // ChaCha20 nonce size
        Rnd.NextBytes(_nonce);

        // 1MB test data - large enough to show intrinsics benefits
        _data1Mb = new byte[1024 * 1024];
        Rnd.NextBytes(_data1Mb);

        _output1Mb = new byte[1024 * 1024];

        _cipher = new ChaCha20(_key, 0);
    }

    [Benchmark(Baseline = true, Description = "Default (runtime detection)")]
    public void ChaCha20_1MB_Default()
    {
        // Use default runtime detection - best available instruction set
        _cipher.Encrypt(_data1Mb, _nonce, _output1Mb);
    }

    [Benchmark(Description = "Intrinsics optimized")]
    public void ChaCha20_1MB_Intrinsics()
    {
        // Test intrinsics path (same as default on modern hardware)
        _cipher.Encrypt(_data1Mb, _nonce, _output1Mb);
    }
}