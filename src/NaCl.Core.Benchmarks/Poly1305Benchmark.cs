namespace NaCl.Core.Benchmarks
{
    using System;

    using BenchmarkDotNet.Attributes;

    [BenchmarkCategory("MAC")]
    [CoreJob(baseline: true), ClrJob/*, MonoJob*/]
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    public class Poly1305Benchmark
    {
        private static Random rnd = new Random(42);

        private byte[] key;
        private byte[] data;

        [Params(10, 100, 1000, 10000)]
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
