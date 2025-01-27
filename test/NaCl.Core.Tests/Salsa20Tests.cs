namespace NaCl.Core.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

using FluentAssertions;
using Xunit;
using Xunit.Abstractions;
using Xunit.Categories;

using Base;
using Internal;
using Vectors;

[Category("CI")]
public class Salsa20Tests
{
    private readonly ITestOutputHelper _output;

    public Salsa20Tests(ITestOutputHelper output) => _output = output;

    private const string EXCEPTION_MESSAGE_NONCE_LENGTH = "*The nonce length in bytes must be 8.";

    private const string LongKeyStream = "A3D1F8292CAB0B2096AB2AA26FC59AAF3EE159B39FC6029EF160D82EC80FA110FF958AB802861180EC006F8C8450030024A2D7744BF564C1782F15DB6681144C65A730622A14AE9A4E95F753289A6D2DBBEE47B457B57DB75C009B287BF240EBE02890581E3628BDBCC9B79E93500CA15F6E10D4EBCAAFC2FB936AF2EC05BBCB1610036E840621D7CE53E4A06822D6073EA0FA8943EDFB70E45B4D2525AE4B616BD08B33F23A7E0B6CD501E80B8E80B7423E7C9D5D900AE2194AF0CF4A74D721534063D3F17BC7993B5B3EC20A373F933B43CEB6987934C1456521F098BA0CB1205109F534F80D4EA1767EA9DFC08BED97BE40C539DD37EC24EAE0C68AC1B56DD0189747A4B8278B1E0E5206EAE893C0E45C76751002F38924B8C9A036CFAB9E3D44C1E323BCE43F2C69EB8212994803C1D2AC00C3B8F97DA6D09F29B974E0DF4D6D36C9D2E88C2D7B73AB399C0920A2996A4727272339D991C6BF45CE63C2DEF3FC9C2625F87EA6268C196829BB1F7E659736AF4B0CC2A771FB0962B19005E53DD880879C052556312BA353B51C26D5F5949464EAECE15ACA240E339BF3C581E7D93D220B1C3C0DE87F65B4F340DAB924EB72072211C41B18770230A3A123619006BE5FD4ABAAFD2BFAD0F34D5FB491DEBEBF5CA9EC92D997B5A171482CC6E949C70759A0B8EC64D590B6FFF6500E8425C3AE4178C2EDE996C0003F6FA76A6D90F49D6D3D128C0DE82EA8C7C16415DDD07081940701677C32D5B5E3BB57A93315474C5B648D31AA7AE52FCD63BF22550900077FF5CF6A5F5148B285E34A57A3DA1BEB0662A20C23857CA8D5D1748F654F54F42F30CD413F408A0C7B31F57AD59E9F152DBDEEA3EA9C3DBB3517615735CFF0226E179C4A9149C6477A2903B338AE308300A86D91043E2AA437C5F2A77A49B547B05BD98CEBE49500FF367CE204157BB3EFD182A8A96FCC31025D4C948105F6762F22357446367B87A01FA3F954D52810CBE5C4EEB04C3AE827973E481F3C38EF14A6F0FE3FB2D89969D2CCB0DFB63D7366D91F29DDBF1EB90B136191745B8AC8B8F0AAEF4D3A1C763D63AED1E76CC7B920979CB8163C413273CA1A563C37B925A0251C9AD31363F978437D92437A0D250C7F221C00F2E13CF371554DF191ECDDB46C95659739A1CDC257A067D9251FE89EA328D313C4D7EF8E33614FFC4C615D3195CD6282D82633067C81E1F563DA307B14253CBF0492256A409E3007EB6A4A7BDA694E1FFA9B5106AB9868CC359B976441C7B362C03E501D8B3FBEF98771A41C4DA542DB8DA4761EA3792695288437DEAC50E7B6A62E6D00B7511A5DB0E567090ADDDFCF0521F6DD62F969D5BE89378DB127219C38931A0AEDBCE784C35D4215B09B1F96732615813753B67846E9505DF974F4B1ECDFBD0C850A9644D720884B80B4FE4CC08508A8A65D1C5F";

    [Fact]
    public void CreateInstanceWhenKeyLengthIsInvalidFails()
    {
        // Arrange, Act & Assert
        Action act = () => new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()], 0);
        act.Should().Throw<CryptographicException>();
    }

    [Theory]
    [InlineData(2, 4)]
    [InlineData(3, 4)]
    [InlineData(4, 3)]
    [InlineData(4, 2)]
    public void EncryptWhenPlaintextIsNotEqualToCiphertextFails(int plaintextLen, int ciphertextLen)
    {
        // Arrange
        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act
        var act = () => cipher.Encrypt(new byte[plaintextLen], new byte[cipher.NonceSizeInBytes], new byte[ciphertextLen]);

        // Assert
        act.Should().Throw<ArgumentException>().WithMessage("The plaintext parameter and the ciphertext do not have the same length.");
    }

    [Fact]
    public void EncryptWhenNonceLengthIsInvalidFails()
    {
        // Arrange
        var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
        var plaintext = new byte[0];
        var ciphertext = new byte[0];

        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act & Assert
        var act = () => cipher.Encrypt(plaintext, nonce, ciphertext);
        act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
    }

    [Fact]
    public void EncryptWhenNonceIsEmptyFails()
    {
        // Arrange
        var nonce = new byte[0];
        var plaintext = new byte[0];
        var ciphertext = new byte[0];

        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act & Assert
        var act = () => cipher.Encrypt(plaintext, nonce, ciphertext);
        act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
    }

    [Fact]
    public void DecryptWhenNonceLengthIsInvalidFails()
    {
        // Arrange
        var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
        var plaintext = new byte[0];
        var ciphertext = new byte[0];

        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act & Assert
        var act = () => cipher.Decrypt(ciphertext, nonce, plaintext);
        act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
    }

    [Fact]
    public void DecryptWhenNonceIsEmptyFails()
    {
        // Arrange
        var nonce = new byte[0];
        var plaintext = new byte[0];
        var ciphertext = new byte[0];

        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act & Assert
        var act = () => cipher.Decrypt(ciphertext, nonce, plaintext);
        act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
    }

    [Theory]
    [InlineData(2, 4)]
    [InlineData(3, 4)]
    [InlineData(4, 3)]
    [InlineData(4, 2)]
    public void DecryptWhenCiphertextIsNotEqualToPlaintextFails(int ciphertextLen, int plaintextLen)
    {
        // Arrange
        var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
        var cipher = new Salsa20(key, 0);
        var nonce = new byte[cipher.NonceSizeInBytes];

        // Act
        var act = () => cipher.Decrypt(new byte[ciphertextLen], nonce, new byte[plaintextLen]);

        // Assert
        act.Should().Throw<ArgumentException>().WithMessage("The ciphertext parameter and the plaintext do not have the same length.");
    }

    [Fact]
    public void EncryptDecrypt1BlockTest()
    {
        // Arrange
        var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
        RandomNumberGenerator.Fill(key);

        var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES];
        RandomNumberGenerator.Fill(nonce);

        var expected = Encoding.UTF8.GetBytes("This is a secret content!!");

        var cipher = new Salsa20(key, 0);

        // Act
        var ciphertext = new byte[expected.Length];
        cipher.Encrypt(expected, nonce, ciphertext);

        var plaintext = new byte[expected.Length];
        cipher.Decrypt(ciphertext, nonce, plaintext);

        // Assert
        plaintext.Should().Equal(expected);
    }

    [Fact]
    public void EncryptDecryptNBlocksTest()
    {
        // Arrange
        var rnd = new Random();
        var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
        var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES];

        for (var i = 0; i < 64; i++)
        {
            RandomNumberGenerator.Fill(key);
            RandomNumberGenerator.Fill(nonce);

            var cipher = new Salsa20(key, 0);

            for (var j = 0; j < 64; j++)
            {
                var expected = new byte[rnd.Next(300)];
                rnd.NextBytes(expected);

                var ciphertext = new byte[expected.Length];
                var plaintext = new byte[expected.Length];

                // Act
                cipher.Encrypt(expected, nonce, ciphertext);
                cipher.Decrypt(ciphertext, nonce, plaintext);

                // Assert
                plaintext.Should().Equal(expected);
            }
        }
    }

    [Fact]
    public void EncryptDecryptLongMessagesTest()
    {
        var rnd = new Random();

        var dataSize = 16;
        while (dataSize <= (1 << 24))
        {
            var plaintext = new byte[dataSize];
            rnd.NextBytes(plaintext);

            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(key);

            var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(nonce);

            var cipher = new Salsa20(key, 0);

            var ciphertext = new byte[plaintext.Length];
            cipher.Encrypt(plaintext, nonce, ciphertext);

            var decrypted = new byte[plaintext.Length];
            cipher.Decrypt(ciphertext, nonce, decrypted);

            decrypted.Should().Equal(plaintext);
            dataSize += 5 * dataSize / 11;
        }
    }

    [Fact]
    public void Salsa20BlockWhenNonceLengthIsEmptyFails()
    {
        // Arrange
        var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

        var salsa20 = new Salsa20(key, 0);
        var nonce = new byte[0];
        var block = new byte[Salsa20.BLOCK_SIZE_IN_BYTES];

        // Act & Assert
        var act = () => salsa20.ProcessKeyStreamBlock(nonce, 0, block);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Salsa20BlockWhenNonceLengthIsInvalidFails()
    {
        // Arrange
        var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

        var salsa20 = new Salsa20(key, 0);
        var nonce = new byte[salsa20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
        var block = new byte[Salsa20.BLOCK_SIZE_IN_BYTES];

        // Act & Assert
        var act = () => salsa20.ProcessKeyStreamBlock(nonce, 0, block);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Salsa20BlockWhenLengthIsInvalidFails()
    {
        // Arrange
        var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

        var salsa20 = new Salsa20(key, 0);
        var nonce = new byte[salsa20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
        var block = new byte[0];

        // Act & Assert
        var act = () => salsa20.ProcessKeyStreamBlock(nonce, 0, block);
        act.Should().Throw<CryptographicException>();
    }

    [Fact]
    public void Salsa20BlockTestVector()
    {
        // Arrange
        var key = CryptoBytes.FromHexString("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".Replace(":", string.Empty));
        var nonce = CryptoBytes.FromHexString("00:00:00:09:00:00:00:4a".Replace(":", string.Empty));
        const int counter = 1;

        // Act
        var salsa20 = new Salsa20(key, 1);
        var output = new byte[Salsa20.BLOCK_SIZE_IN_BYTES];
        salsa20.ProcessKeyStreamBlock(nonce, counter, output);

        // Assert
        var expected = new uint[16]
        {
            3649387971u, 3432934094u, 2867581180u, 544842727u,
            3442094382u, 3233001746u, 2484653980u, 586338650u,
            3037335121u, 3388889956u, 1351682463u, 2284954070u,
            3021171268u, 2617586057u, 3288245149u, 2763695160u
        };

        output.ToUInt16Array().Should().Equal(expected);
    }

    [Theory]
    [MemberData(nameof(Salsa20TestData))]
    public void Salsa20TestVectors(Salsa20TestVector test)
    {
        _output.WriteLine($"Salsa20 - {test.Name}");

        var input = new byte[512];
        var output = new byte[512];

        var cipher = new Salsa20(test.Key, 0);
        cipher.Encrypt(input, test.IV, output);

        ToBlock1(output).Should().Be(test.ExpectedBlock1);
        ToBlock4(output).Should().Be(test.ExpectedBlock4);
        ToBlock5(output).Should().Be(test.ExpectedBlock5);
        ToBlock8(output).Should().Be(test.ExpectedBlock8);
    }

    public static IEnumerable<object[]> Salsa20TestData => ParseTestVectors(GetTestVector()).Select(d => new object[] { d });

    [Theory]
    [InlineData(33)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(511)]
    [InlineData(512)]
    [InlineData(1023)]
    [InlineData(1024)]
    public void Salsa20VariableLengthCiphers(int size)
    {
        var input = new byte[size];
        var output = new byte[size];

        var nonce = new byte[8];
        Array.Fill(nonce, (byte)2);

        var key = new byte[32];
        Array.Fill(key, (byte)1);

        var cipher = new Salsa20(key, 0);
        cipher.Encrypt(input, nonce, output);
        var value = Convert.ToHexString(output);

        value.Should().Be(LongKeyStream[..(size*2)]);
    }

    private static string GetTestVector()
    {
        try
        {
            using var client = new HttpClient();
            return client.GetStringAsync("https://github.com/das-labor/legacy/raw/master/microcontroller-2/arm-crypto-lib/testvectors/salsa20-256.64-verified.test-vectors").Result;
        }
        catch (Exception)
        {
            return File.ReadAllText(@"Vectors\salsa20-256.64-verified.test-vectors");
        }
    }

    private static IList<Salsa20TestVector> ParseTestVectors(string raw)
    {
        var lines = raw.Split(new[] {'\r', '\n'});

        var result = new List<Salsa20TestVector>();

        string ReadValue(string toFind, int idx, int len)
        {
            var toFindIdx = lines[idx].IndexOf(toFind, StringComparison.Ordinal) + toFind.Length;
            return lines[idx].Substring(toFindIdx, len);
        }

        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].StartsWith("Set "))
                continue;

            // We skip Set 6 vector tests for now...
            if (!lines[i + 8].Contains("stream[192..255] = "))
                continue;

            var name = lines[i].Replace(":", "");

            var key = ReadValue("key = ", i + 1, 32);
            key += lines[i + 2].Trim();

            var iv = ReadValue("IV = ", i + 3, 16);

            var block1 = ReadValue("stream[0..63] = ", i + 4, 32);
            block1 += lines[i + 5].Trim();
            block1 += lines[i + 6].Trim();
            block1 += lines[i + 7].Trim();

            var block4 = ReadValue("stream[192..255] = ", i + 8, 32);
            block4 += lines[i + 9].Trim();
            block4 += lines[i + 10].Trim();
            block4 += lines[i + 11].Trim();

            var block5 = ReadValue("stream[256..319] = ", i + 12, 32);
            block5 += lines[i + 13].Trim();
            block5 += lines[i + 14].Trim();
            block5 += lines[i + 15].Trim();

            var block8 = ReadValue("stream[448..511] = ", i + 16, 32);
            block8 += lines[i + 17].Trim();
            block8 += lines[i + 18].Trim();
            block8 += lines[i + 19].Trim();

            result.Add(new Salsa20TestVector(name, key, iv, block1, block4, block5, block8));
            i += 20;
        }

        return result;
    }

    private static string ToBlock1(byte[] output) => CryptoBytes.ToHexStringUpper(output[0..64]);

    private static string ToBlock4(byte[] output) => CryptoBytes.ToHexStringUpper(output[192..256]);

    private static string ToBlock5(byte[] output) => CryptoBytes.ToHexStringUpper(output[256..320]);

    private static string ToBlock8(byte[] output) => CryptoBytes.ToHexStringUpper(output[448..512]);
}