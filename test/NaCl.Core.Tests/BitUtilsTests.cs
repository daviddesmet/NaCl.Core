namespace NaCl.Core.Tests;

using Xunit;
using Xunit.Categories;

using Internal;

[Category("CI")]
public class BitUtilsTests
{
    [Theory(DisplayName = "BitOps RotateLeft UInt32")]
    [InlineData(0b00000000_00000000_00000000_00000001u, int.MaxValue, 0b10000000_00000000_00000000_00000000u)] // % 32 = 31
    [InlineData(0b01000000_00000001_00000000_00000001u, 3, 0b00000000_00001000_00000000_00001010u)]
    [InlineData(0b01000000_00000001_00000000_00000001u, 2, 0b00000000_00000100_00000000_00000101u)]
    [InlineData(0b01010101_01010101_01010101_01010101u, 1, 0b10101010_10101010_10101010_10101010u)]
    [InlineData(0b01010101_11111111_01010101_01010101u, 0, 0b01010101_11111111_01010101_01010101u)]
    [InlineData(0b00000000_00000000_00000000_00000001u, -1, 0b10000000_00000000_00000000_00000000u)]
    [InlineData(0b00000000_00000000_00000000_00000001u, -2, 0b01000000_00000000_00000000_00000000u)]
    [InlineData(0b00000000_00000000_00000000_00000001u, -3, 0b00100000_00000000_00000000_00000000u)]
    [InlineData(0b01010101_11111111_01010101_01010101u, int.MinValue, 0b01010101_11111111_01010101_01010101u)] // % 32 = 0
    public static void BitOps_RotateLeft_uint(uint n, int offset, uint expected)
    {
        Assert.Equal(expected, BitUtils.RotateLeft(n, offset));
    }

    [Fact(DisplayName = "BitOps RotateLeft UInt64")]
    public static void BitOps_RotateLeft_ulong()
    {
        ulong value = 0b01010101_01010101_01010101_01010101_01010101_01010101_01010101_01010101ul;
        Assert.Equal(0b10101010_10101010_10101010_10101010_10101010_10101010_10101010_10101010ul, BitUtils.RotateLeft(value, 1));
        Assert.Equal(0b01010101_01010101_01010101_01010101_01010101_01010101_01010101_01010101ul, BitUtils.RotateLeft(value, 2));
        Assert.Equal(0b10101010_10101010_10101010_10101010_10101010_10101010_10101010_10101010ul, BitUtils.RotateLeft(value, 3));
        Assert.Equal(value, BitUtils.RotateLeft(value, int.MinValue)); // % 64 = 0
        Assert.Equal(BitUtils.RotateLeft(value, 63), BitUtils.RotateLeft(value, int.MaxValue)); // % 64 = 63
    }

    /*
    [Theory(DisplayName = "BitOps RotateRight UInt32")]
    [InlineData(0b10000000_00000000_00000000_00000000u, int.MaxValue, 0b00000000_00000000_00000000_00000001u)] // % 32 = 31
    [InlineData(0b00000000_00001000_00000000_00001010u, 3, 0b01000000_00000001_00000000_00000001u)]
    [InlineData(0b00000000_00000100_00000000_00000101u, 2, 0b01000000_00000001_00000000_00000001u)]
    [InlineData(0b01010101_01010101_01010101_01010101u, 1, 0b10101010_10101010_10101010_10101010u)]
    [InlineData(0b01010101_11111111_01010101_01010101u, 0, 0b01010101_11111111_01010101_01010101u)]
    [InlineData(0b10000000_00000000_00000000_00000000u, -1, 0b00000000_00000000_00000000_00000001u)]
    [InlineData(0b00000000_00000000_00000000_00000001u, -2, 0b00000000_00000000_00000000_00000100u)]
    [InlineData(0b01000000_00000000_00000000_00000000u, -3, 0b00000000_00000000_00000000_00000010u)]
    [InlineData(0b01010101_11111111_01010101_01010101u, int.MinValue, 0b01010101_11111111_01010101_01010101u)] // % 32 = 0
    public static void BitOps_RotateRight_uint(uint n, int offset, uint expected)
    {
        Assert.Equal(expected, BitUtils.RotateRight(n, offset));
    }

    [Fact(DisplayName = "BitOps RotateRight UInt64")]
    public static void BitOps_RotateRight_ulong()
    {
        ulong value = 0b01010101_01010101_01010101_01010101_01010101_01010101_01010101_01010101ul;
        Assert.Equal(0b10101010_10101010_10101010_10101010_10101010_10101010_10101010_10101010ul, BitUtils.RotateRight(value, 1));
        Assert.Equal(0b01010101_01010101_01010101_01010101_01010101_01010101_01010101_01010101ul, BitUtils.RotateRight(value, 2));
        Assert.Equal(0b10101010_10101010_10101010_10101010_10101010_10101010_10101010_10101010ul, BitUtils.RotateRight(value, 3));
        Assert.Equal(value, BitUtils.RotateRight(value, int.MinValue)); // % 64 = 0
        Assert.Equal(BitUtils.RotateLeft(value, 63), BitUtils.RotateRight(value, int.MaxValue)); // % 64 = 63
    }
    */
}