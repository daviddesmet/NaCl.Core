using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NaCl.Core.Internal;

namespace NaCl.Core.Tests.Vectors
{
    public class Avx2TestVector
    {
        public byte[] Key { get; private set; }
        public byte[] PlainText { get; private set; }
        public byte[] Nonce { get; private set; }
        public byte[] CipherText { get; private set; }
        public int InitialCounter { get; private set; }
        public byte[] Aad { get; private set; }
        public byte[] Tag { get; private set; }

        public string Id { get; private set; } // used to identify the benchmark test

        public Avx2TestVector(string key, string plaintext, string nonce, string ciphertext, int initialCounter, string id)
        {
            Key = CryptoBytes.FromHexString(key);
            PlainText = CryptoBytes.FromHexString(plaintext);
            Nonce = CryptoBytes.FromHexString(nonce);
            CipherText = CryptoBytes.FromHexString(ciphertext);
            InitialCounter = initialCounter;
            Id = id;
        }

        public Avx2TestVector(string plaintext, string aad, string key, string nonce, string ciphertext, string tag, string id)
        {
            PlainText = CryptoBytes.FromHexString(plaintext);
            Aad = CryptoBytes.FromHexString(aad);
            Key = CryptoBytes.FromHexString(key);
            Nonce = CryptoBytes.FromHexString(nonce);
            CipherText = CryptoBytes.FromHexString(ciphertext);
            Tag = CryptoBytes.FromHexString(tag);
            Id = id;
        }

        public override string ToString() => Id;

        public static Avx2TestVector[] Avx2TestVectors =
{
            // Tests against the test vectors in Section 2.3.2 of RFC 8439.
            // https://tools.ietf.org/html/rfc8439#section-2.3.2
            new Avx2TestVector(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7",
                "000000000000004a00000000",
                "224e53f0441edfe627d72d64b46e13e29c020d91293910f56656d0f782eed167aa1a288056452cb59d505ee6c106bd1b497d8873f20b02fad2181677cc407f8829e736dc7b2649066a83b463a0008a317685663e24ecda24abb09f619851071a59ea0cb97ee64aeea90e80a6fc7010448312067007556cd6f082c69345ecba92486c84cfea161bc7b9fc646acbdd7d6a393f19d555d83bdd0eb150349ad7bf4faad3f10e5c6a281730c594c3de6b70cafd31c4782e142aa0f9843c07b268d5ac6e1237243e48cf9bf8ac8de3f9a9025cb12ef196f96210a1bdac5f7b39aca5de296cdfad6722403c441cce0b287faf4077fae180e150d38e1828bf86855c33d9cb50b7a119b83e0fe47e5be0953ddd574fd028d4a355a51a101f4017ce5c3fb2115e956184c47f5ab5e03f442cc57b8af9e5ea8ff78116001a128197f1af4702c9bc95732fcd862a33a25e4f4cd11ef437b56bdf60c1247bbf372a94c4765b3c5a7d74e982304444c1cc8dd27c7bf1bc6b112a6b37909cf8c1df454410506a609a1a20573febf209f4a904c6e4acac1b1eaeffc6ac3d7152d54e81dbd268d97f177a4707b3acb02fb000e7adb4df2e92bebb328173a56b7189432ff26310ff89784d5857e526617b29a2b547b7c7e3b3f1abcb51a307c8492c4fb81fcca70107f3633550fa7a91b48019d1fd42d7736cb50c4aa062474a264ef5fe25d6de885fe13f3e9ce20eb7164202176c441d5108e0bb5df663b4f8e86ac2577faa8bc1779cb3d4a16cd292161549949e461cd8dfb79780c056be048962aa9e2437cc3bc6c3d3e699139326d3790d2650d4107e8671859ec941f676f01eff44719932932ee016c67519572973434d4da98366b09e1ee7ff66a4847e53aa22d72da621eeab3afddc5d7d0424eda5558b980ef8858276bc05df8f72cedfc1178636d85ad0555a6d66780629f9760cd184e4bd98d57eebd0070baa706250570f2175014c7073776ced5aabeef5d3149e4748f44b764c9033731253334b097217de77a9e1b9f3a6cac67201f1172506b83c9c6c369b39615da36afbf2bfd25b7f9eb239b11556a62a29031a00cdb54c7e2cc93b2034c7ede67e207869b6527b4606e83bcba9b84d4fe3f1d133f92f0654a78c443dfda8056b8dd74e9612cf45b9e0ae085bffe0f472ec97c89c71be9a7ffcda99cabc3358399a00474b00f5bcded6e65fbf2e961b0b2271fac738ce645395ec4076ea9dccf9f75e2ba9d3508805526a170fe4b1af607a8debb6bf5b9d23a6b2ea6c87eca616520e06f233ae16a905a8588877b0f16580fdc14ba6b8ba4178c5e4255ff2a38d3560231395d55ebe84069f14e52ab3529413943f0fa4b9fc7000e8b54d867a67d229c1107ae5b4742744d9722451201f28d4243177da",
                1, "Test Vector #1"),
        };
    }
}
