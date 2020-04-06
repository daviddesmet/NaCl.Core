namespace NaCl.Core.Benchmarks
{
    using System;
    using System.Collections.Generic;

    using Base;
    using Internal;

    using BenchmarkDotNet.Attributes;
    using BenchmarkDotNet.Jobs;

    [BenchmarkCategory("AEAD")]
    [SimpleJob(RuntimeMoniker.Net472, baseline: true)]
    [SimpleJob(RuntimeMoniker.NetCoreApp31)]
    [SimpleJob(RuntimeMoniker.NetCoreApp50)]
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    public class XChaCha20Poly1305Benchmark
    {
        private static Random rnd = new Random(42);

        private byte[] key;
        private byte[] nonce;
        private byte[] aad;
        private byte[] message;
        private XChaCha20Poly1305 aead;

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
            key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            nonce = new byte[24];
            rnd.NextBytes(nonce);

            message = new byte[Size];
            rnd.NextBytes(message);

            aad = new byte[24];
            rnd.NextBytes(aad);

            aead = new XChaCha20Poly1305(key);
        }

        [Benchmark]
        [BenchmarkCategory("Encryption")]
        public byte[] Encrypt() => aead.Encrypt(message, aad, nonce);

        [Benchmark]
        [BenchmarkCategory("Decryption")]
        [ArgumentsSource(nameof(TestVectors))]
        public byte[] Decrypt(Tests.Vectors.XChaCha20Poly1305TestVector test)
        {
            var aead = new XChaCha20Poly1305(test.Key);
            return aead.Decrypt(CryptoBytes.Combine(test.Nonce, test.CipherText, test.Tag), test.Aad);
        }

        public IEnumerable<object> TestVectors()
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
}
