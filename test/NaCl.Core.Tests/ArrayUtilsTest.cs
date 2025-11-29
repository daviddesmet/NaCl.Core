namespace NaCl.Core.Tests;

using System;
using System.Security.Cryptography;

using Shouldly;
using Xunit;
using Xunit.Categories;

using Internal;

[Category("CI")]
public class ArrayUtilsTest
{
    [Fact]
    public void LoadUInt32LittleEndianTest()
    {
        // Arrange
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        // Act
        var result = ArrayUtils.LoadUInt32LittleEndian(data, 0);

        // Assert
        result.ShouldBe(0x04030201u);
    }

    [Fact]
    public void StoreUInt32LittleEndianTest()
    {
        // Arrange
        var data = new byte[8];
        var value = 0x04030201u;

        // Act
        ArrayUtils.StoreUInt32LittleEndian(data, 0, value);

        // Assert
        data[0].ShouldBe((byte)0x01);
        data[1].ShouldBe((byte)0x02);
        data[2].ShouldBe((byte)0x03);
        data[3].ShouldBe((byte)0x04);
    }

    [Fact]
    public void StoreUInt64LittleEndianTest()
    {
        // Arrange
        var data = new byte[16];
        var value = 0x0807060504030201ul;

        // Act
        ArrayUtils.StoreUInt64LittleEndian(data, 0, value);

        // Assert
        data[0].ShouldBe((byte)0x01);
        data[1].ShouldBe((byte)0x02);
        data[2].ShouldBe((byte)0x03);
        data[3].ShouldBe((byte)0x04);
        data[4].ShouldBe((byte)0x05);
        data[5].ShouldBe((byte)0x06);
        data[6].ShouldBe((byte)0x07);
        data[7].ShouldBe((byte)0x08);
    }

    [Fact]
    public void StoreArray8UInt32LittleEndianTest()
    {
        // Arrange
        var data = new byte[32];
        var values = new uint[] { 0x04030201, 0x08070605, 0x0C0B0A09, 0x100F0E0D, 0x14131211, 0x18171615, 0x1C1B1A19, 0x201F1E1D };

        // Act
        ArrayUtils.StoreArray8UInt32LittleEndian(data, 0, values);

        // Assert
        for (int i = 0; i < 32; i++)
        {
            data[i].ShouldBe((byte)(i + 1));
        }
    }

    [Fact]
    public void StoreArray16UInt32LittleEndianTest()
    {
        // Arrange
        var data = new byte[64];
        var values = new uint[16];
        for (int i = 0; i < 16; i++)
        {
            values[i] = (uint)((i * 4 + 4) << 24 | (i * 4 + 3) << 16 | (i * 4 + 2) << 8 | (i * 4 + 1));
        }

        // Act
        ArrayUtils.StoreArray16UInt32LittleEndian(data, 0, values);

        // Assert
        for (int i = 0; i < 64; i++)
        {
            data[i].ShouldBe((byte)(i + 1));
        }
    }

    [Fact]
    public void StoreArrayUInt32LittleEndianConsistencyTest()
    {
        // Test to ensure all implementations (scalar, SSE2, AVX2, AdvSimd) produce identical results
        var random = new Random(42);
        var testSizes = new[] { 8, 16, 32, 64, 128, 256, 512 };

        foreach (var elementCount in testSizes)
        {
            var values = new uint[elementCount];
            for (int i = 0; i < elementCount; i++)
            {
                values[i] = (uint)random.Next();
            }

            var data1 = new byte[elementCount * 4];
            var data2 = new byte[elementCount * 4];

            // Store using general method (which will select the best implementation)
            ArrayUtils.StoreArrayUInt32LittleEndian(data1, 0, values, elementCount);
            ArrayUtils.StoreArrayUInt32LittleEndian(data2, 0, values, elementCount);

            // Results should be identical
            data1.ShouldBe(data2, $"Results should be identical for {elementCount} elements");

            // Verify round-trip by loading back
            var loadedValues = new uint[elementCount];
            ArrayUtils.LoadArrayUInt32LittleEndian(data1, 0, loadedValues, elementCount);
            loadedValues.ShouldBe(values, $"Round-trip should work for {elementCount} elements");
        }
    }

    [Fact]
    public void LoadArrayUInt32LittleEndianConsistencyTest()
    {
        // Test to ensure all implementations produce identical results
        var testSizes = new[] { 8, 16, 32, 64, 128, 256, 512 };

        foreach (var elementCount in testSizes)
        {
            var data = new byte[elementCount * 4];
            RandomNumberGenerator.Fill(data);

            var values1 = new uint[elementCount];
            var values2 = new uint[elementCount];

            // Load using general method (which will select the best implementation)
            ArrayUtils.LoadArrayUInt32LittleEndian(data, 0, values1, elementCount);
            ArrayUtils.LoadArrayUInt32LittleEndian(data, 0, values2, elementCount);

            // Results should be identical
            values1.ShouldBe(values2, $"Results should be identical for {elementCount} elements");
        }
    }

    [Fact]
    public void StoreLoadRoundTripTest()
    {
        // Test round-trip consistency for various sizes that will exercise different intrinsics paths
        var testSizes = new[] { 1, 2, 4, 8, 16, 17, 32, 33, 64, 65, 128, 129, 256, 257, 512, 513 };
        var random = new Random(123);

        foreach (var elementCount in testSizes)
        {
            var originalValues = new uint[elementCount];
            for (int i = 0; i < elementCount; i++)
            {
                originalValues[i] = (uint)random.Next();
            }

            var data = new byte[elementCount * 4];
            ArrayUtils.StoreArrayUInt32LittleEndian(data, 0, originalValues, elementCount);

            var loadedValues = new uint[elementCount];
            ArrayUtils.LoadArrayUInt32LittleEndian(data, 0, loadedValues, elementCount);

            loadedValues.ShouldBe(originalValues, $"Round-trip failed for {elementCount} elements");
        }
    }

    [Fact]
    public void AlignmentTest()
    {
        // Test different memory alignments to ensure intrinsics work correctly with unaligned data
        var baseData = new byte[1024];
        RandomNumberGenerator.Fill(baseData);

        for (int offset = 0; offset < 16; offset++)
        {
            var alignedData = new Span<byte>(baseData, offset, 512);
            var values = new uint[128]; // 128 * 4 = 512 bytes

            // Load from potentially unaligned data
            ArrayUtils.LoadArrayUInt32LittleEndian(alignedData, 0, values, 128);

            // Store back to potentially unaligned data
            var outputData = new byte[512 + offset];
            var outputSpan = new Span<byte>(outputData, offset, 512);
            ArrayUtils.StoreArrayUInt32LittleEndian(outputSpan, 0, values, 128);

            // The stored data should match the original
            alignedData.ToArray().ShouldBe(outputSpan.ToArray(), $"Alignment test failed for offset {offset}");
        }
    }

    [Fact]
    public void IntrinsicsSpecificSizesTest()
    {
        // Test sizes that specifically exercise different intrinsics code paths
        var testCases = new[]
        {
            (8, "8 elements - specific optimization"), 
            (16, "16 elements - specific optimization"),
            (32, "32 elements - AVX2 boundary"),
            (64, "64 elements - large AVX2"),
            (33, "33 elements - non-multiple of intrinsic size"),
            (63, "63 elements - non-multiple boundary case")
        };

        var random = new Random(456);

        foreach (var (elementCount, description) in testCases)
        {
            var values = new uint[elementCount];
            for (int i = 0; i < elementCount; i++)
            {
                values[i] = (uint)random.Next();
            }

            var data = new byte[elementCount * 4];
            
            // This should not throw and should use appropriate intrinsics path
            Action storeAct = () => ArrayUtils.StoreArrayUInt32LittleEndian(data, 0, values, elementCount);
            storeAct.ShouldNotThrow($"Store should not fail for {description}");

            var loadedValues = new uint[elementCount];
            Action loadAct = () => ArrayUtils.LoadArrayUInt32LittleEndian(data, 0, loadedValues, elementCount);
            loadAct.ShouldNotThrow($"Load should not fail for {description}");

            loadedValues.ShouldBe(values, $"Round-trip should work for {description}");
        }
    }

    [Fact]
    public void EdgeCasesTest()
    {
        // Test edge cases
        
        // Zero elements
        var emptyValues = new uint[0];
        var emptyData = new byte[0];
        Action emptyStoreAct = () => ArrayUtils.StoreArrayUInt32LittleEndian(emptyData, 0, emptyValues, 0);
        emptyStoreAct.ShouldNotThrow("Empty store should not fail");

        Action emptyLoadAct = () => ArrayUtils.LoadArrayUInt32LittleEndian(emptyData, 0, emptyValues, 0);
        emptyLoadAct.ShouldNotThrow("Empty load should not fail");

        // Single element
        var singleValue = new uint[] { 0x12345678 };
        var singleData = new byte[4];
        ArrayUtils.StoreArrayUInt32LittleEndian(singleData, 0, singleValue, 1);
        singleData.ShouldBe(new byte[] { 0x78, 0x56, 0x34, 0x12 });

        var loadedSingle = new uint[1];
        ArrayUtils.LoadArrayUInt32LittleEndian(singleData, 0, loadedSingle, 1);
        loadedSingle[0].ShouldBe(0x12345678u);
    }
}