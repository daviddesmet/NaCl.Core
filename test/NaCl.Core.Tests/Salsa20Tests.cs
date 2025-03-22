namespace NaCl.Core.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

using Shouldly;
using Xunit;
using Xunit.Abstractions;
using Xunit.Categories;

using Base;
using Internal;
using Vectors;

[Category("CI")]
public class Salsa20Tests(ITestOutputHelper output)
{
    private const string ExceptionMessageNonceLength = "*The nonce length in bytes must be 8.";

    [Fact]
    public void CreateInstanceWhenKeyLengthIsInvalidFails()
    {
        // Arrange, Act & Assert
        Action act = () => new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()], 0);
        act.ShouldThrow<CryptographicException>();
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
        act.ShouldThrow<ArgumentException>("The plaintext parameter and the ciphertext do not have the same length.");
    }

    [Fact]
    public void EncryptWhenNonceLengthIsInvalidFails()
    {
        // Arrange
        var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
        var plaintext = Array.Empty<byte>();
        var ciphertext = Array.Empty<byte>();

        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act & Assert
        var act = () => cipher.Encrypt(plaintext, nonce, ciphertext);
        act.ShouldThrow<ArgumentException>(ExceptionMessageNonceLength);
    }

    [Fact]
    public void EncryptWhenNonceIsEmptyFails()
    {
        // Arrange
        var nonce = Array.Empty<byte>();
        var plaintext = Array.Empty<byte>();
        var ciphertext = Array.Empty<byte>();

        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act & Assert
        var act = () => cipher.Encrypt(plaintext, nonce, ciphertext);
        act.ShouldThrow<ArgumentException>(ExceptionMessageNonceLength);
    }

    [Fact]
    public void DecryptWhenNonceLengthIsInvalidFails()
    {
        // Arrange
        var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
        var plaintext = Array.Empty<byte>();
        var ciphertext = Array.Empty<byte>();

        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act & Assert
        var act = () => cipher.Decrypt(ciphertext, nonce, plaintext);
        act.ShouldThrow<ArgumentException>(ExceptionMessageNonceLength);
    }

    [Fact]
    public void DecryptWhenNonceIsEmptyFails()
    {
        // Arrange
        var nonce = Array.Empty<byte>();
        var plaintext = Array.Empty<byte>();
        var ciphertext = Array.Empty<byte>();

        var cipher = new Salsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

        // Act & Assert
        var act = () => cipher.Decrypt(ciphertext, nonce, plaintext);
        act.ShouldThrow<ArgumentException>(ExceptionMessageNonceLength);
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
        act.ShouldThrow<ArgumentException>("The ciphertext parameter and the plaintext do not have the same length.");
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
        plaintext.ShouldBe(expected);
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
                plaintext.ShouldBe(expected);
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

            decrypted.ShouldBe(plaintext);
            dataSize += 5 * dataSize / 11;
        }
    }

    [Fact]
    public void Salsa20BlockWhenNonceLengthIsEmptyFails()
    {
        // Arrange
        var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

        var salsa20 = new Salsa20(key, 0);
        var nonce = Array.Empty<byte>();
        var block = new byte[Salsa20.BLOCK_SIZE_IN_BYTES];

        // Act & Assert
        var act = () => salsa20.ProcessKeyStreamBlock(nonce, 0, block);
        act.ShouldThrow<CryptographicException>();
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
        act.ShouldThrow<CryptographicException>();
    }

    [Fact]
    public void Salsa20BlockWhenLengthIsInvalidFails()
    {
        // Arrange
        var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

        var salsa20 = new Salsa20(key, 0);
        var nonce = new byte[salsa20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
        var block = Array.Empty<byte>();

        // Act & Assert
        var act = () => salsa20.ProcessKeyStreamBlock(nonce, 0, block);
        act.ShouldThrow<CryptographicException>();
    }

    [Fact]
    public void Salsa20TestVectors()
    {
        var tests = ParseTestVectors(GetTestVector());

        foreach (var test in tests)
        {
            output.WriteLine($"Salsa20 - {test.Name}");

            var input = new byte[512];
            var output1 = new byte[512];

            var cipher = new Salsa20(test.Key, 0);
            cipher.Encrypt(input, test.IV, output1);

            ToBlock1(output1).ShouldBe(test.ExpectedBlock1);
            ToBlock4(output1).ShouldBe(test.ExpectedBlock4);
            ToBlock5(output1).ShouldBe(test.ExpectedBlock5);
            ToBlock8(output1).ShouldBe(test.ExpectedBlock8);
        }
    }

    private string GetTestVector()
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

    private IList<Salsa20TestVector> ParseTestVectors(string raw)
    {
        var lines = raw.Split(new[] {'\r', '\n'});

        var result = new List<Salsa20TestVector>();

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

        string ReadValue(string toFind, int idx, int len)
        {
            var toFindIdx = lines[idx].IndexOf(toFind, StringComparison.Ordinal) + toFind.Length;
            return lines[idx].Substring(toFindIdx, len);
        }
    }

    private static string ToBlock1(byte[] output) => CryptoBytes.ToHexStringUpper(output[0..64]);

    private static string ToBlock4(byte[] output) => CryptoBytes.ToHexStringUpper(output[192..256]);

    private static string ToBlock5(byte[] output) => CryptoBytes.ToHexStringUpper(output[256..320]);

    private static string ToBlock8(byte[] output) => CryptoBytes.ToHexStringUpper(output[448..512]);
}