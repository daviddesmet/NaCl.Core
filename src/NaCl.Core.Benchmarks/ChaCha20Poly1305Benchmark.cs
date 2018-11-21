namespace NaCl.Core.Benchmarks
{
    using System;

    using Base;
    using BenchmarkDotNet.Attributes;

    [BenchmarkCategory("AEAD")]
    [CoreJob(baseline: true), ClrJob/*, MonoJob*/]
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    public class ChaCha20Poly1305Benchmark
    {
        private static Random rnd = new Random(42);

        private byte[] key;
        private byte[] aad;
        private byte[] message;
        private ChaCha20Poly1305 aead;

        [Params(10, 100, 1000, 10000)]
        public int Size { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            message = new byte[Size];
            rnd.NextBytes(message);

            aad = new byte[16];
            rnd.NextBytes(aad);

            aead = new ChaCha20Poly1305(key);
        }

        [Benchmark]
        public byte[] Encrypt() => aead.Encrypt(message, aad);

        // TODO: Use the encrypt value (from Encrypt method) to benchmark decryption
        //[Benchmark]
        //public byte[] Decrypt(byte[] ciphertext) => aead.Decrypt(ciphertext, aad);
    }
}
