namespace NaCl.Core.Benchmarks;

using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using Internal;

[SimpleJob(RuntimeMoniker.Net90)]
[BenchmarkCategory("Hardware Intrinsics")]
[MemoryDiagnoser]
[RPlotExporter, RankColumn]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class ArrayUtilsIntrinsicsBenchmark
{
    private static readonly Random Rnd = new(42);

    private Memory<byte> _byteBuffer;
    private Memory<uint> _uintBuffer;

    [Params(
        8,      // 8 uint32s (minimum for AVX2 optimization)
        16,     // 16 uint32s (ChaCha20/Salsa20 block size)
        64,     // 64 uint32s (larger block)
        256)]   // 256 uint32s (very large block)
    public int ArraySize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _byteBuffer = new byte[ArraySize * sizeof(uint)];
        Rnd.NextBytes(_byteBuffer.Span);

        _uintBuffer = new uint[ArraySize];
        for (var i = 0; i < ArraySize; i++)
        {
            _uintBuffer.Span[i] = (uint)Rnd.Next();
        }
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Store")]
    public void StoreArrayDefault()
    {
        // Use default runtime detection - best available instruction set
        var output = new byte[ArraySize * sizeof(uint)];
        ArrayUtils.StoreArrayUInt32LittleEndian(output, 0, _uintBuffer.Span, ArraySize);
    }

    [Benchmark]
    [BenchmarkCategory("Store")]
    public void StoreArrayIntrinsics()
    {
        // Test intrinsics path (same as default on modern hardware)
        var output = new byte[ArraySize * sizeof(uint)];
        ArrayUtils.StoreArrayUInt32LittleEndian(output, 0, _uintBuffer.Span, ArraySize);
    }

    [Benchmark]
    [BenchmarkCategory("Load")]
    public void LoadArrayDefault()
    {
        // Use default runtime detection - best available instruction set
        var output = new uint[ArraySize];
        ArrayUtils.LoadArrayUInt32LittleEndian(_byteBuffer.Span, 0, output, ArraySize);
    }

    [Benchmark]
    [BenchmarkCategory("Load")]
    public void LoadArrayIntrinsics()
    {
        // Test intrinsics path (same as default on modern hardware)
        var output = new uint[ArraySize];
        ArrayUtils.LoadArrayUInt32LittleEndian(_byteBuffer.Span, 0, output, ArraySize);
    }
}