﻿namespace NaCl.Core.Benchmarks
{
    using System;

    using BenchmarkDotNet.Attributes;
    using BenchmarkDotNet.Jobs;

    [BenchmarkCategory("MAC")]
    [SimpleJob(RuntimeMoniker.Net472, baseline: true)]
    [SimpleJob(RuntimeMoniker.NetCoreApp31)]
    [SimpleJob(RuntimeMoniker.NetCoreApp50)]
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    public class Poly1305Benchmark
    {
        private static Random rnd = new Random(42);

        private byte[] key;
        private byte[] data;

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
            key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            data = new byte[Size];
            rnd.NextBytes(data);
        }

        [Benchmark(Description = "ComputeMac")]
        public byte[] Compute() => Poly1305.ComputeMac(key, data);

        // TODO: Use the mac value (from Compute method) to benchmark verification
        //[Benchmark(Description = "VerifyMac")]
        //public byte[] Verify(byte[] mac) => Poly1305.VerifyMac(key, data, mac);
    }
}
