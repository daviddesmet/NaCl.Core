﻿namespace NaCl.Core.Tests;

using System;
using System.Linq;

using FluentAssertions;
using Xunit;
using Xunit.Categories;

using Internal;

[Category("CI")]
public class CryptoBytesTest
{
    private readonly byte[] _bytes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

    private const string HexStringUpper =
        "000102030405060708090A0B0C0D0E0F" +
        "101112131415161718191A1B1C1D1E1F" +
        "202122232425262728292A2B2C2D2E2F" +
        "303132333435363738393A3B3C3D3E3F" +
        "404142434445464748494A4B4C4D4E4F" +
        "505152535455565758595A5B5C5D5E5F" +
        "606162636465666768696A6B6C6D6E6F" +
        "707172737475767778797A7B7C7D7E7F" +
        "808182838485868788898A8B8C8D8E8F" +
        "909192939495969798999A9B9C9D9E9F" +
        "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF" +
        "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF" +
        "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF" +
        "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF" +
        "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF" +
        "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";

    private const string HexStringLower =
        "000102030405060708090a0b0c0d0e0f" +
        "101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f" +
        "303132333435363738393a3b3c3d3e3f" +
        "404142434445464748494a4b4c4d4e4f" +
        "505152535455565758595a5b5c5d5e5f" +
        "606162636465666768696a6b6c6d6e6f" +
        "707172737475767778797a7b7c7d7e7f" +
        "808182838485868788898a8b8c8d8e8f" +
        "909192939495969798999a9b9c9d9e9f" +
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    private const string Base64String =
        "AAECAwQFBgcICQoL" +
        "DA0ODxAREhMUFRYX" +
        "GBkaGxwdHh8gISIj" +
        "JCUmJygpKissLS4v" +
        "MDEyMzQ1Njc4OTo7" +
        "PD0+P0BBQkNERUZH" +
        "SElKS0xNTk9QUVJT" +
        "VFVWV1hZWltcXV5f" +
        "YGFiY2RlZmdoaWpr" +
        "bG1ub3BxcnN0dXZ3" +
        "eHl6e3x9fn+AgYKD" +
        "hIWGh4iJiouMjY6P" +
        "kJGSk5SVlpeYmZqb" +
        "nJ2en6ChoqOkpaan" +
        "qKmqq6ytrq+wsbKz" +
        "tLW2t7i5uru8vb6/" +
        "wMHCw8TFxsfIycrL" +
        "zM3Oz9DR0tPU1dbX" +
        "2Nna29zd3t/g4eLj" +
        "5OXm5+jp6uvs7e7v" +
        "8PHy8/T19vf4+fr7" +
        "/P3+/w==";

    [Fact]
    public void ToHexStringUpper()
    {
        CryptoBytes.ToHexStringUpper(_bytes).Should().Be(HexStringUpper);
    }

    [Fact]
    public void ToHexStringLower()
    {
        CryptoBytes.ToHexStringLower(_bytes).Should().Be(HexStringLower);
    }

    [Fact]
    public void ToHexStringLowerNull()
    {
        CryptoBytes.ToHexStringLower(null).Should().BeNull();
    }

    [Fact]
    public void ToHexStringUpperNull()
    {
        CryptoBytes.ToHexStringUpper(null).Should().BeNull();
    }

    [Fact]
    public void FromHexStringUpperCase()
    {
        _bytes.SequenceEqual(CryptoBytes.FromHexString(HexStringUpper)).Should().BeTrue();
    }

    [Fact]
    public void FromHexStringLowerCase()
    {
        _bytes.SequenceEqual(CryptoBytes.FromHexString(HexStringLower)).Should().BeTrue();
    }

    [Fact]
    public void FromHexStringNull()
    {
        CryptoBytes.FromHexString(null).Should().BeNull();
    }

    [Fact]
    public void FromHexStringWithOddLengthFails()
    {
        Action act = () => CryptoBytes.FromHexString("A");
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void FromHexStringWithInvalidCharactersFails()
    {
        Action act = () => CryptoBytes.FromHexString("AQ");
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void ToBase64String()
    {
        CryptoBytes.ToBase64String(_bytes).Should().Be(Base64String);
    }

    [Fact]
    public void FromBase64String()
    {
        _bytes.SequenceEqual(CryptoBytes.FromBase64String(Base64String)).Should().BeTrue();
    }


    [Fact]
    public void ToBase64StringNull()
    {
        CryptoBytes.ToBase64String(null).Should().BeNull();
    }

    [Fact]
    public void FromBase64StringNull()
    {
        CryptoBytes.FromBase64String(null).Should().BeNull();
    }

    [Fact]
    public void Wipe()
    {
        var bytes = (byte[])_bytes.Clone();
        CryptoBytes.Wipe(bytes);
        bytes.All(b => b == 0).Should().BeTrue();
    }

    [Fact]
    public void WipeInterval()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var wipedBytes = new byte[] { 1, 2, 0, 0, 0, 0, 0, 8, 9, 10 };
        CryptoBytes.Wipe(bytes, 2, 5);
        TestHelpers.AssertEqualBytes(wipedBytes, bytes);
    }

    [Fact]
    public void WipeSegment()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var wipedBytes = new byte[] { 1, 2, 0, 0, 0, 0, 0, 8, 9, 10 };
        CryptoBytes.Wipe(new ArraySegment<byte>(bytes, 2, 5));
        TestHelpers.AssertEqualBytes(wipedBytes, bytes);
    }

    [Fact]
    public void ConstantTimeEqualsSuccess()
    {
        var x = new byte[] { 1, 2, 3 };
        var y = new byte[] { 1, 2, 3 };
        CryptoBytes.ConstantTimeEquals(x, y).Should().BeTrue();
    }

    [Fact]
    public void ConstantTimeEqualsFail()
    {
        var x = new byte[] { 1, 2, 3 };
        foreach (var y in x.WithChangedBit())
            CryptoBytes.ConstantTimeEquals(x, y).Should().BeFalse();
    }

    [Fact]
    public void ConstantTimeEqualsSegmentsSuccess()
    {
        var x = new byte[] { 1, 2, 3 };
        var y = new byte[] { 1, 2, 3 };
        CryptoBytes.ConstantTimeEquals(x.Pad(), y.Pad()).Should().BeTrue();
    }

    [Fact]
    public void ConstantTimeEqualsSegmentsFail()
    {
        var x = new byte[] { 1, 2, 3 };
        foreach (var y in x.WithChangedBit())
            CryptoBytes.ConstantTimeEquals(x.Pad(), y.Pad()).Should().BeFalse();
    }

    [Fact]
    public void ConstantTimeEqualsRangeSuccess()
    {
        var x = new byte[] { 1, 2, 3 };
        var y = new byte[] { 1, 2, 3 };
        var paddedX = x.Pad();
        var paddedY = y.Pad();
        CryptoBytes.ConstantTimeEquals(paddedX.Array, paddedX.Offset, paddedY.Array, paddedY.Offset, paddedX.Count).Should().BeTrue();
    }

    [Fact]
    public void ConstantTimeEqualsRangeFail()
    {
        var x = new byte[] { 1, 2, 3 };
        foreach (var y in x.WithChangedBit())
        {
            var paddedX = x.Pad();
            var paddedY = y.Pad();
            CryptoBytes.ConstantTimeEquals(paddedX.Array, paddedX.Offset, paddedY.Array, paddedY.Offset, paddedX.Count).Should().BeFalse();
        }
    }

    #region Argument Validation

    /*
    [Fact]
    public void ConstantTimeEqualsXMustNotBeNull()
    {
        Assert.Throws<ArgumentNullException>(() => CryptoBytes.ConstantTimeEquals(null, new byte[1]));
    }

    [Fact]
    public void ConstantTimeEqualsYMustNotBeNull()
    {
        Assert.Throws<ArgumentNullException>(() => CryptoBytes.ConstantTimeEquals(new byte[1], null));
    }
    */

    [Fact]
    public void ConstantTimeEqualsXAndYMustHaveSameLength()
    {
        Action act = () => CryptoBytes.ConstantTimeEquals(new byte[1], new byte[2]);
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ConstantTimeEqualsSegmentsMustHaveSameLength()
    {
        var x = new byte[5];
        var y = new byte[5];

        Action act = () => CryptoBytes.ConstantTimeEquals(new ArraySegment<byte>(x, 0, 4), new ArraySegment<byte>(y, 0, 5));
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ConstantTimeEqualsSegmentsXMustNotBeNull()
    {
        Action act = () => CryptoBytes.ConstantTimeEquals(default, new ArraySegment<byte>(new byte[1]));
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ConstantTimeEqualsSegmentsYMustNotBeNull()
    {
        Action act = () => CryptoBytes.ConstantTimeEquals(new ArraySegment<byte>(new byte[1]), default);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void WipeNullFails()
    {
        Action act = () => CryptoBytes.Wipe(null);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ConstantTimeEqualsRangeXmustNotBeNull()
    {
        Action act = () => CryptoBytes.ConstantTimeEquals(null, 0, new byte[10], 0, 1);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ConstantTimeEqualsRangeYmustNotBeNull()
    {
        Action act = () => CryptoBytes.ConstantTimeEquals(new byte[10], 0, null, 0, 1);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ConstantTimeEqualsRangeXoffsetMustNotBeNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBytes.ConstantTimeEquals(new byte[10], -1, new byte[10], 0, 1));
    }

    [Fact]
    public void ConstantTimeEqualsRangeYoffsetMustNotBeNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBytes.ConstantTimeEquals(new byte[10], 0, new byte[10], -1, 1));
    }

    [Fact]
    public void ConstantTimeEqualsRangeLengthMustNotBeNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBytes.ConstantTimeEquals(new byte[10], 0, new byte[10], 0, -1));
    }


    [Fact]
    public void ConstantTimeEqualsRangeLengthTooBigX()
    {
        Assert.Throws<ArgumentException>(() => CryptoBytes.ConstantTimeEquals(new byte[10], 8, new byte[10], 1, 7));
    }

    [Fact]
    public void ConstantTimeEqualsRangeLengthTooBigY()
    {
        Assert.Throws<ArgumentException>(() => CryptoBytes.ConstantTimeEquals(new byte[10], 1, new byte[10], 8, 7));
    }

    [Fact]
    public void WipeSegmentNullFails()
    {
        Assert.Throws<ArgumentNullException>(() => CryptoBytes.Wipe(default(ArraySegment<byte>)));
    }

    [Fact]
    public void WipeRangeNullFails()
    {
        Assert.Throws<ArgumentNullException>(() => CryptoBytes.Wipe(null, 0, 0));
    }

    [Fact]
    public void WipeRangeNegativeOffsetFails()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBytes.Wipe(new byte[10], -1, 0));
    }

    [Fact]
    public void WipeRangeNegativeLengthFails()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CryptoBytes.Wipe(new byte[10], 0, -1));
    }

    [Fact]
    public void WipeRangeTooLargeLengthFails()
    {
        Assert.Throws<ArgumentException>(() => CryptoBytes.Wipe(new byte[10], 8, 8));
    }
    #endregion
}