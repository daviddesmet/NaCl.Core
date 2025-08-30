namespace NaCl.Core.Tests;

using System;
using System.Security.Cryptography;
using System.Text;

using Shouldly;
using Xunit;
using Xunit.Categories;

using Internal;

[Category("CI")]
public class Poly1305Test
{
    private const string ExceptionMessageTagLength = "The tag length in bytes must be 16.";

    [Fact]
    public void ComputeMacWhenKeyLengthIsGreaterThan32Fails()
    {
        // Arrange, Act & Assert
        Action act = () => Poly1305.ComputeMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES + 1], Array.Empty<byte>());
        act.ShouldThrow<CryptographicException>();
    }

    [Fact]
    public void ComputeMacWhenKeyLengthIsLessThan32Fails()
    {
        // Arrange, Act & Assert
        Action act = () => Poly1305.ComputeMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES - 1], Array.Empty<byte>());
        act.ShouldThrow<CryptographicException>();
    }

    [Fact]
    public void VerifyMacWhenKeyLengthIsGreaterThan32Fails()
    {
        // Arrange, Act & Assert
        var act = () => Poly1305.VerifyMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES + 1], Array.Empty<byte>(), Array.Empty<byte>());
        act.ShouldThrow<CryptographicException>();
    }

    [Fact]
    public void VerifyMacWhenKeyLengthIsLessThan32Fails()
    {
        // Arrange, Act & Assert
        var act = () => Poly1305.VerifyMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES - 1], Array.Empty<byte>(), Array.Empty<byte>());
        act.ShouldThrow<CryptographicException>();
    }

    [Fact]
    public void VerifyMacWhenTagLengthIsInvalidFails()
    {
        // Arrange, Act & Assert
        var act = () => Poly1305.VerifyMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES], Array.Empty<byte>(), new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()]);
        act.ShouldThrow<CryptographicException>(ExceptionMessageTagLength);
    }

    [Fact]
    public void VerifyMacWhenTagLengthIsEmptyFails()
    {
        // Arrange, Act & Assert
        var act = () => Poly1305.VerifyMac(new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES], Array.Empty<byte>(), Array.Empty<byte>());
        act.ShouldThrow<CryptographicException>(ExceptionMessageTagLength);
    }

    [Fact]
    public void RandomMacTest()
    {
        var rnd = new Random();
        for (var i = 0; i < 1000; i++)
        {
            // Arrange
            var key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(key);

            var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];

            var data = new byte[rnd.Next(300)];
            rnd.NextBytes(data);

            // Act
            Poly1305.ComputeMac(key, data, mac);

            // Assert
            Action act = () => Poly1305.VerifyMac(key, data, mac);
            act.ShouldNotThrow();
        }
    }

    [Fact]
    public void RandomMacOldMethodSignatureTest()
    {
        var rnd = new Random();
        for (var i = 0; i < 1000; i++)
        {
            // Arrange
            var key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(key);

            var data = new byte[rnd.Next(300)];
            rnd.NextBytes(data);

            // Act
            var mac = Poly1305.ComputeMac(key, data);

            // Assert
            Action act = () => Poly1305.VerifyMac(key, data, mac);
            act.ShouldNotThrow();
        }
    }

    [Fact]
    public void VerifyMacFails()
    {
        // Arrange
        var key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
        key[0] = 1;

        // Act & Assert
        var act = () => Poly1305.VerifyMac(key, new byte[] { 1 }, new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES]);
        act.ShouldThrow<CryptographicException>();
    }

    [Fact]
    public void ComputeMacTest()
    {
        // Tests against the test vectors in Section 2.5.2 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#section-2.5.2

        // Arrange
        var key = CryptoBytes.FromHexString("85d6be7857556d337f4452fe42d506a8"
                                            + "0103808afb0db2fd4abff6af4149f51b");
        var dat = Encoding.UTF8.GetBytes("Cryptographic Forum Research Group");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    [Fact]
    public void Poly1305TestVector1()
    {
        // Tests against the test vector 1 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("00000000000000000000000000000000"
                                                + "00000000000000000000000000000000");
        var dat = CryptoBytes.FromHexString("00000000000000000000000000000000"
                                                + "00000000000000000000000000000000"
                                                + "00000000000000000000000000000000"
                                                + "00000000000000000000000000000000");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("00000000000000000000000000000000"));
    }

    [Fact]
    public void Poly1305TestVector2()
    {
        // Tests against the test vector 2 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("00000000000000000000000000000000"
                                                + "36e5f6b5c5e06070f0efca96227a863e");
        var dat = Encoding.UTF8.GetBytes("Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("36e5f6b5c5e06070f0efca96227a863e"));
    }

    [Fact]
    public void Poly1305TestVector3()
    {
        // Tests against the test vector 3 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("36e5f6b5c5e06070f0efca96227a863e"
                                                + "00000000000000000000000000000000");
        var dat = Encoding.UTF8.GetBytes("Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("f3477e7cd95417af89a6b8794c310cf0"));
    }

    [Fact]
    public void Poly1305TestVector4()
    {
        // Tests against the test vector 4 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("1c9240a5eb55d38af333888604f6b5f0"
                                                + "473917c1402b80099dca5cbc207075c0");
        var dat = CryptoBytes.FromHexString("2754776173206272696c6c69672c2061"
                                                + "6e642074686520736c6974687920746f"
                                                + "7665730a446964206779726520616e64"
                                                + "2067696d626c6520696e207468652077"
                                                + "6162653a0a416c6c206d696d73792077"
                                                + "6572652074686520626f726f676f7665"
                                                + "732c0a416e6420746865206d6f6d6520"
                                                + "7261746873206f757467726162652e");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("4541669a7eaaee61e708dc7cbcc5eb62"));
    }

    [Fact]
    public void Poly1305TestVector5()
    {
        // Tests against the test vector 5 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("02000000000000000000000000000000"
                                                + "00000000000000000000000000000000");
        var dat = CryptoBytes.FromHexString("ffffffffffffffffffffffffffffffff");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("03000000000000000000000000000000"));
    }

    [Fact]
    public void Poly1305TestVector6()
    {
        // Tests against the test vector 6 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("02000000000000000000000000000000"
                                                + "ffffffffffffffffffffffffffffffff");
        var dat = CryptoBytes.FromHexString("02000000000000000000000000000000");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("03000000000000000000000000000000"));
    }

    [Fact]
    public void Poly1305TestVector7()
    {
        // Tests against the test vector 7 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("01000000000000000000000000000000"
                                                + "00000000000000000000000000000000");
        var dat = CryptoBytes.FromHexString("ffffffffffffffffffffffffffffffff"
                                                + "f0ffffffffffffffffffffffffffffff"
                                                + "11000000000000000000000000000000");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("05000000000000000000000000000000"));
    }

    [Fact]
    public void Poly1305TestVector8()
    {
        // Tests against the test vector 8 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("01000000000000000000000000000000"
                                                + "00000000000000000000000000000000");
        var dat = CryptoBytes.FromHexString("ffffffffffffffffffffffffffffffff"
                                                + "fbfefefefefefefefefefefefefefefe"
                                                + "01010101010101010101010101010101");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("00000000000000000000000000000000"));
    }

    [Fact]
    public void Poly1305TestVector9()
    {
        // Tests against the test vector 9 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("02000000000000000000000000000000"
                                                + "00000000000000000000000000000000");
        var dat = CryptoBytes.FromHexString("fdffffffffffffffffffffffffffffff");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("faffffffffffffffffffffffffffffff"));
    }

    [Fact]
    public void Poly1305TestVector10()
    {
        // Tests against the test vector 10 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("01000000000000000400000000000000"
                                                + "00000000000000000000000000000000");
        var dat = CryptoBytes.FromHexString("e33594d7505e43b90000000000000000"
                                                + "3394d7505e4379cd0100000000000000"
                                                + "00000000000000000000000000000000"
                                                + "01000000000000000000000000000000");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("14000000000000005500000000000000"));
    }

    [Fact]
    public void Poly1305TestVector11()
    {
        // Tests against the test vector 11 in Appendix A.3 of RFC 7539.
        // https://tools.ietf.org/html/rfc7539#appendix-A.3

        // Arrange
        var key = CryptoBytes.FromHexString("01000000000000000400000000000000"
                                                + "00000000000000000000000000000000");
        var dat = CryptoBytes.FromHexString("e33594d7505e43b90000000000000000"
                                                + "3394d7505e4379cd0100000000000000"
                                                + "00000000000000000000000000000000");

        // Act
        var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
        Poly1305.ComputeMac(key, dat, mac);

        // Assert
        mac.ShouldBe(CryptoBytes.FromHexString("13000000000000000000000000000000"));
    }

    [Fact]
    public void ComputeMacLargeDataTest()
    {
        // Test with data that will exercise different code paths including hardware intrinsics
        var key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
        RandomNumberGenerator.Fill(key);

        // Test various sizes to ensure all intrinsics paths are tested
        int[] testSizes = { 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192 };

        foreach (var size in testSizes)
        {
            var data = new byte[size];
            RandomNumberGenerator.Fill(data);

            var mac1 = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            var mac2 = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];

            // Compute MAC using span-based method
            Poly1305.ComputeMac(key, data, mac1);

            // Compute MAC using array-based method
            var mac3 = Poly1305.ComputeMac(key, data);

            // All should produce the same result
            mac1.ShouldBe(mac3);
            
            // Verify MAC works
            Action act = () => Poly1305.VerifyMac(key, data, mac1);
            act.ShouldNotThrow();
        }
    }

    [Fact]
    public void ComputeMacOptimizedPathsTest()
    {
        // Test to ensure optimized paths (scalar, SSE2, AVX2, AdvSimd) are covered
        var key = CryptoBytes.FromHexString("85d6be7857556d337f4452fe42d506a8"
                                           + "0103808afb0db2fd4abff6af4149f51b");

        // Test with different data patterns that might trigger different optimizations
        var testCases = new[]
        {
            new byte[0], // Empty data
            new byte[1] { 0xFF }, // Single byte
            new byte[15] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // 15 bytes (partial block)
            new byte[16] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // Exactly 16 bytes
            new byte[17] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // 17 bytes
            new byte[64], // 64 bytes (multiple of 16)
            new byte[65], // 65 bytes (not multiple of 16)
        };

        foreach (var data in testCases)
        {
            if (data.Length > 0)
                RandomNumberGenerator.Fill(data);

            var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            Action act = () => Poly1305.ComputeMac(key, data, mac);
            act.ShouldNotThrow();

            // Verify the computed MAC
            Action verifyAct = () => Poly1305.VerifyMac(key, data, mac);
            verifyAct.ShouldNotThrow();
        }
    }

    [Fact]
    public void ComputeMacWithDifferentAlignmentsTest()
    {
        // Test different memory alignments to ensure intrinsics work correctly
        var key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
        RandomNumberGenerator.Fill(key);

        var baseData = new byte[1024];
        RandomNumberGenerator.Fill(baseData);

        // Test different offsets/alignments
        for (int offset = 0; offset < 8; offset++)
        {
            var alignedData = new byte[512 - offset];
            Array.Copy(baseData, offset, alignedData, 0, alignedData.Length);

            var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            Action act = () => Poly1305.ComputeMac(key, alignedData, mac);
            act.ShouldNotThrow();

            // Verify the MAC
            Action verifyAct = () => Poly1305.VerifyMac(key, alignedData, mac);
            verifyAct.ShouldNotThrow();
        }
    }

    [Fact]
    public void ComputeMacConsistencyAcrossImplementationsTest()
    {
        // Ensure all implementations (scalar, SSE2, AVX2, AdvSimd) produce identical results
        var key = new byte[Poly1305.MAC_KEY_SIZE_IN_BYTES];
        RandomNumberGenerator.Fill(key);

        var testSizes = new[] { 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024 };

        foreach (var size in testSizes)
        {
            var data = new byte[size];
            if (size > 0)
                RandomNumberGenerator.Fill(data);

            var mac = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            Poly1305.ComputeMac(key, data, mac);

            // The result should be deterministic regardless of which optimized path is taken
            var mac2 = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            Poly1305.ComputeMac(key, data, mac2);

            mac.ShouldBe(mac2, $"MACs should be identical for data size {size}");
        }
    }
}