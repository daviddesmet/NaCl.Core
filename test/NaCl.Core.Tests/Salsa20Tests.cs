namespace NaCl.Core.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net.Http;
    using System.Security.Cryptography;

    using FluentAssertions;
    using Xunit;
    using Xunit.Abstractions;
    using Xunit.Categories;

    using Internal;
    using Vectors;

    [Category("CI")]
    public class Salsa20Tests
    {
        private readonly ITestOutputHelper _output;

        public Salsa20Tests(ITestOutputHelper output) => _output = output;

        [Fact]
        public void Salsa20TestVectors()
        {
            var tests = ParseTestVectors(GetTestVector());

            foreach (var test in tests)
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
        }

        [Fact]
        public void Salsa20NaclTestVector()
        {
            // 8. Example of the long stream, ref: https://cr.yp.to/highspeed/naclcrypto-20090310.pdf

            // Arrange
            var secondKey = new byte[32]
            {
                0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9,
                0x53, 0x62, 0x9b, 0x73, 0x38, 0x20, 0x77, 0x88,
                0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9,
                0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4
            };
            var nonceSuffix = new byte[8]
            {
                0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
            };

            var cipher = new Salsa20(secondKey, 0);

            var input = new byte[16];
            var output = new byte[64];

            // Act
            for (var i = 0; i < 8; i++)
                input[i] = nonceSuffix[i];

            cipher.ProcessKeyStreamBlock(nonceSuffix, 0, output);

            // Assert
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(output);
            var result = CryptoBytes.ToHexStringLower(hash);

            result.Should().Be("662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2");
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
}