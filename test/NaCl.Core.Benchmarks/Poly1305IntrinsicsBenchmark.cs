namespace NaCl.Core.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;

[SimpleJob(RuntimeMoniker.Net90)]
[BenchmarkCategory("Hardware Intrinsics")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class Poly1305IntrinsicsBenchmark
{
    private static readonly Random Rnd = new(42);

    private Memory<byte> _key;
    private Memory<byte> _data;

    [Params(
        (int)1E+3,  // 1 KB - small data
        (int)1E+5,  // 100 KB - medium data
        (int)1E+6)] // 1 MB - large data (most relevant for intrinsics benefits)
    public int Size { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
        Rnd.NextBytes(_key.Span);

        _data = new byte[Size];
        Rnd.NextBytes(_data.Span);
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Default")]
    public void ComputeDefault()
    {
        // Use default runtime detection - best available instruction set
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(_key.Span, _data.Span, mac);
    }

    [Benchmark]
    [BenchmarkCategory("Intrinsics")]
    public void ComputeIntrinsics()
    {
        // Test intrinsics path (same as default on modern hardware)
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(_key.Span, _data.Span, mac);
    }
}