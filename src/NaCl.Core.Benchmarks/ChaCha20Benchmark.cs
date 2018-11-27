namespace NaCl.Core.Benchmarks
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Base;
    using Internal;

    using BenchmarkDotNet.Attributes;

    [BenchmarkCategory("Stream Cipher")]
    [CoreJob(baseline: true), ClrJob/*, MonoJob*/]
    [MemoryDiagnoser]
    [RPlotExporter, RankColumn]
    public class ChaCha20Benchmark
    {
        private static Random rnd = new Random(42);

        private byte[] key;
        private byte[] nonce;
        private byte[] message;
        private ChaCha20 cipher;

        [Params(10, 100, 1000, 10000)]
        public int Size { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            nonce = new byte[12];
            rnd.NextBytes(nonce);

            message = new byte[Size];
            rnd.NextBytes(message);

            cipher = new ChaCha20(key, 0);
        }

        [Benchmark]
        public byte[] Encrypt() => cipher.Encrypt(message, nonce);

        [Benchmark]
        [ArgumentsSource(nameof(TestVectors))]
        public byte[] Decrypt(Tests.Crypto.Rfc8439TestVector test)
        {
            var cipher = new ChaCha20(test.Key, test.InitialCounter);
            return cipher.Decrypt(CryptoBytes.Combine(test.Nonce, test.CipherText));
        }

        public IEnumerable<object> TestVectors()
        {
            //foreach (var test in Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors)
            //    yield return test;
            
            yield return Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors[0];
            yield return Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors[1];
            yield return Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors[2];
            yield return Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors[3];
            yield return Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors[4];
            yield return Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors[5];
            yield return Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors[6];
            yield return Tests.Crypto.Rfc8439TestVector.Rfc8439TestVectors[7];
        }

        // TODO: Use the encrypt value (from Encrypt method) to benchmark decryption
        //[Benchmark]
        //public byte[] Decrypt(byte[] ciphertext) => aead.Decrypt(ciphertext, aad);
    }
}
