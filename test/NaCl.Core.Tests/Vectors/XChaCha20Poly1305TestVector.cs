namespace NaCl.Core.Tests.Vectors
{
    using Internal;

    public class XChaCha20Poly1305TestVector
    {
        public byte[] Key { get; private set; }
        public byte[] Nonce { get; private set; }
        public byte[] PlainText { get; private set; }
        public byte[] Aad { get; private set; }
        public byte[] CipherText { get; private set; }
        public byte[] Tag { get; private set; }

        public string Id { get; private set; } // used to identify the benchmark test

        public XChaCha20Poly1305TestVector(string key, string nonce, string plaintext, string aad, string ciphertext, string tag, string id)
        {
            Key = CryptoBytes.FromHexString(key);
            Nonce = CryptoBytes.FromHexString(nonce);
            PlainText = CryptoBytes.FromHexString(plaintext);
            Aad = CryptoBytes.FromHexString(aad);
            CipherText = CryptoBytes.FromHexString(ciphertext);
            Tag = CryptoBytes.FromHexString(tag);
            Id = id;
        }

        public override string ToString() => $"Test Vector {Id}";

        public static XChaCha20Poly1305TestVector[] TestVectors =
        {
            // From libsodium's test/default/aead_xchacha20poly1305.c
            // see test/default/aead_xchacha20poly1305.exp for ciphertext values.
            new XChaCha20Poly1305TestVector(
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "07000000404142434445464748494a4b0000000000000000",
                "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620"
                    + "4920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574"
                    + "7572652c2073756e73637265656e20776f756c642062652069742e",
                "50515253c0c1c2c3c4c5c6c7",
                "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8b89ad929530a1bb3ab5e69f24c"
                    + "7f6070c8f840c9abb4f69fbfc8a7ff5126faeebbb55805ee9c1cf2ce5a57263287aec5780f04ec324c35"
                    + "14122cfc3231fc1a8b718a62863730a2702bb76366116bed09e0fd",
                "5c6d84b6b0c1abaf249d5dd0f7f5a7ea", "#1"),
            new XChaCha20Poly1305TestVector(
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "07000000404142434445464748494a4b0000000000000000",
                "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620"
                    + "4920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574"
                    + "7572652c2073756e73637265656e20776f756c642062652069742e",
                "" /* empty aad */,
                "453c0693a7407f04ff4c56aedb17a3c0a1afff01174930fc22287c33dbcf0ac8b89ad929530a1bb3ab5e69f24c"
                    + "7f6070c8f840c9abb4f69fbfc8a7ff5126faeebbb55805ee9c1cf2ce5a57263287aec5780f04ec324c35"
                    + "14122cfc3231fc1a8b718a62863730a2702bb76366116bed09e0fd",
                "d4c860b7074be894fac9697399be5cc1", "#2"),
            // From https://tools.ietf.org/html/draft-arciszewski-xchacha-01.
            new XChaCha20Poly1305TestVector(
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "404142434445464748494a4b4c4d4e4f5051525354555657",
                "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a20496620"
                    + "4920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074686520667574"
                    + "7572652c2073756e73637265656e20776f756c642062652069742e",
                "50515253c0c1c2c3c4c5c6c7",
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4e"
                    + "da7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc36948"
                    + "8f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
                "c0875924c1c7987947deafd8780acf49", "#3")
        };
    }
}
