namespace NaCl.Core.Tests.Vectors;

using NaCl.Core.Internal;

public class Salsa20TestVector
{
    public Salsa20TestVector(string name, string key, string iv, string block1, string block4, string block5, string block8)
    {
        Name = name;
        Key = CryptoBytes.FromHexString(key);
        IV = CryptoBytes.FromHexString(iv);

        ExpectedBlock1 = block1;
        ExpectedBlock4 = block4;
        ExpectedBlock5 = block5;
        ExpectedBlock8 = block8;
    }

    public string Name { get; }

    public byte[] Key { get; }

    public byte[] IV { get; }

    public string ExpectedBlock1 { get; }

    public string ExpectedBlock4 { get; }

    public string ExpectedBlock5 { get; }

    public string ExpectedBlock8 { get; }

    public override string ToString() => Name;
}