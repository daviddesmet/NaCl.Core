namespace NaCl.Core.Tests.Vectors;

using Internal;

public class HChaCha20TestVector
{
    public byte[] Key { get; private set; }
    public byte[] Input { get; private set; }
    public byte[] Output { get; private set; }

    public HChaCha20TestVector(string key, string input, string output)
    {
        Key = CryptoBytes.FromHexString(key);
        Input = CryptoBytes.FromHexString(input);
        Output = CryptoBytes.FromHexString(output);
    }

    public static HChaCha20TestVector[] HChaCha20TestVectors = {
        // From libsodium's test/default/xchacha20.c (tv_hchacha20).
        new HChaCha20TestVector(
            "24f11cce8a1b3d61e441561a696c1c1b7e173d084fd4812425435a8896a013dc",
            "d9660c5900ae19ddad28d6e06e45fe5e",
            "5966b3eec3bff1189f831f06afe4d4e3be97fa9235ec8c20d08acfbbb4e851e3"),
        new HChaCha20TestVector(
            "80a5f6272031e18bb9bcd84f3385da65e7731b7039f13f5e3d475364cd4d42f7",
            "c0eccc384b44c88e92c57eb2d5ca4dfa",
            "6ed11741f724009a640a44fce7320954c46e18e0d7ae063bdbc8d7cf372709df"),
        new HChaCha20TestVector(
            "cb1fc686c0eec11a89438b6f4013bf110e7171dace3297f3a657a309b3199629",
            "fcd49b93e5f8f299227e64d40dc864a3",
            "84b7e96937a1a0a406bb7162eeaad34308d49de60fd2f7ec9dc6a79cbab2ca34"),
        new HChaCha20TestVector(
            "6640f4d80af5496ca1bc2cfff1fefbe99638dbceaabd7d0ade118999d45f053d",
            "31f59ceeeafdbfe8cae7914caeba90d6",
            "9af4697d2f5574a44834a2c2ae1a0505af9f5d869dbe381a994a18eb374c36a0"),
        new HChaCha20TestVector(
            "0693ff36d971225a44ac92c092c60b399e672e4cc5aafd5e31426f123787ac27",
            "3a6293da061da405db45be1731d5fc4d",
            "f87b38609142c01095bfc425573bb3c698f9ae866b7e4216840b9c4caf3b0865"),
        new HChaCha20TestVector(
            "809539bd2639a23bf83578700f055f313561c7785a4a19fc9114086915eee551",
            "780c65d6a3318e479c02141d3f0b3918",
            "902ea8ce4680c09395ce71874d242f84274243a156938aaa2dd37ac5be382b42"),
        new HChaCha20TestVector(
            "1a170ddf25a4fd69b648926e6d794e73408805835c64b2c70efddd8cd1c56ce0",
            "05dbee10de87eb0c5acb2b66ebbe67d3",
            "a4e20b634c77d7db908d387b48ec2b370059db916e8ea7716dc07238532d5981"),
        new HChaCha20TestVector(
            "3b354e4bb69b5b4a1126f509e84cad49f18c9f5f29f0be0c821316a6986e15a6",
            "d8a89af02f4b8b2901d8321796388b6c",
            "9816cb1a5b61993735a4b161b51ed2265b696e7ded5309c229a5a99f53534fbc"),
        new HChaCha20TestVector(
            "4b9a818892e15a530db50dd2832e95ee192e5ed6afffb408bd624a0c4e12a081",
            "a9079c551de70501be0286d1bc78b045",
            "ebc5224cf41ea97473683b6c2f38a084bf6e1feaaeff62676db59d5b719d999b"),
        new HChaCha20TestVector(
            "c49758f00003714c38f1d4972bde57ee8271f543b91e07ebce56b554eb7fa6a7",
            "31f0204e10cf4f2035f9e62bb5ba7303",
            "0dd8cc400f702d2c06ed920be52048a287076b86480ae273c6d568a2e9e7518c"),
        // From https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.1.
        new HChaCha20TestVector(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000000090000004a0000000031415927",
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    };
}