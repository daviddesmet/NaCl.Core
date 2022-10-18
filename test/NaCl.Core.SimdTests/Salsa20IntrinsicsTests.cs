namespace NaCl.Core.SimdTests
{
    using System;
    using System.Collections.Generic;
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
    using System.Linq;
    using NaCl.Core.Base.SalsaCore;
    using NaCl.Core.SimdTests.Vectors;

    public class Salsa20IntrinsicsTests
    {
        private readonly ITestOutputHelper _output;

        public Salsa20IntrinsicsTests(ITestOutputHelper output) => _output = output;

        [Fact]
        public void HSalsa20IntrinsicsTestVector1()
        {
            // 8. Example of the long stream, ref: https://cr.yp.to/highspeed/naclcrypto-20090310.pdf

            // Arrange
            var shared = new byte[32]
            {
                0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
                0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
                0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
            };
            var zero = new byte[32];
            var c = new byte[16] // SIGMA
            {
                0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
                0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b
            };

            var salsa20 = new XSalsa20(shared);
            var cipher = new Salsa20CoreIntrinsics(salsa20);

            // Act
            var firstKey = new byte[32];
            cipher.HSalsa20(firstKey, zero);

            // Assert
            firstKey.Should().Equal(new byte[]
            {
                0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
                0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
                0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
            });
        }

        [Fact]
        public void HSalsa20IntrinsicsTestVector2()
        {
            // 8. Example of the long stream, ref: https://cr.yp.to/highspeed/naclcrypto-20090310.pdf

            // Arrange
            var firstKey = new byte[32]
            {
                0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
                0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
                0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
            };
            var noncePrefix = new byte[16]
            {
                0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
                0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6
            };
            var c = new byte[16] // SIGMA
            {
                0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
                0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b
            };

            var salsa20 = new XSalsa20(firstKey);
            var cipher = new Salsa20CoreIntrinsics(salsa20);

            // Act
            var secondKey = new byte[32];
            cipher.HSalsa20(secondKey, noncePrefix);

            // Assert
            secondKey.Should().Equal(new byte[]
            {
                0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9,
                0x53, 0x62, 0x9b, 0x73, 0x38, 0x20, 0x77, 0x88,
                0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9,
                0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4
            });
        }

        [Fact]
        public void HSalsa20IntrinsicsTestVector3()
        {
            // 8. Example of the long stream, ref: https://cr.yp.to/highspeed/naclcrypto-20090310.pdf

            // Arrange
            var k = new byte[32]
            {
                0xee, 0x30, 0x4f, 0xca, 0x27, 0x00, 0x8d, 0x8c,
                0x12, 0x6f, 0x90, 0x02, 0x79, 0x01, 0xd8, 0x0f,
                0x7f, 0x1d, 0x8b, 0x8d, 0xc9, 0x36, 0xcf, 0x3b,
                0x9f, 0x81, 0x96, 0x92, 0x82, 0x7e, 0x57, 0x77
            };
            var n = new byte[16]
            {
                0x81, 0x91, 0x8e, 0xf2, 0xa5, 0xe0, 0xda, 0x9b,
                0x3e, 0x90, 0x60, 0x52, 0x1e, 0x4b, 0xb3, 0x52
            };

            var salsa20 = new XSalsa20(k);
            var cipher = new Salsa20CoreIntrinsics(salsa20);

            // Act
            var output = new byte[32];
            cipher.HSalsa20(output, n);

            // Assert
            output.Should().Equal(new byte[]
            {
                0xbc, 0x1b, 0x30, 0xfc, 0x07, 0x2c, 0xc1, 0x40,
                0x75, 0xe4, 0xba, 0xa7, 0x31, 0xb5, 0xa8, 0x45,
                0xea, 0x9b, 0x11, 0xe9, 0xa5, 0x19, 0x1f, 0x94,
                0xe1, 0x8c, 0xba, 0x8f, 0xd8, 0x21, 0xa7, 0xcd
            });
        }

        [Fact]
        public void IntrinsicsEncryptDecrypt1BlockTest()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(key);

            var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(nonce);

            var expected = Encoding.UTF8.GetBytes("This is a secret content!!");

            var salsa20 = new Salsa20(key, 0);
            var cipher = new Salsa20CoreIntrinsics(salsa20);

            // Act
            var ciphertext = new byte[expected.Length];
            cipher.Process(nonce, ciphertext, expected);

            var plaintext = new byte[expected.Length];
            cipher.Process(nonce, plaintext, ciphertext);

            // Assert
            plaintext.Should().Equal(expected);
        }

        [Fact]
        public void IntrinsicsEncryptDecryptNBlocksTest()
        {
            // Arrange
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES];

            for (var i = 0; i < 64; i++)
            {
                RandomNumberGenerator.Fill(key);
                RandomNumberGenerator.Fill(nonce);

                var salsa20 = new Salsa20(key, 0);
                var cipher = new Salsa20CoreIntrinsics(salsa20);

                for (var j = 0; j < 64; j++)
                {
                    var expected = new byte[rnd.Next(300)];
                    rnd.NextBytes(expected);

                    var ciphertext = new byte[expected.Length];
                    var plaintext = new byte[expected.Length];

                    // Act
                    cipher.Process(nonce, ciphertext, expected);
                    cipher.Process(nonce, plaintext, ciphertext);

                    // Assert
                    plaintext.Should().Equal(expected);
                }
            }
        }

        [Fact]
        public void IntrinsicsEncryptDecryptLongMessagesTest()
        {
            var rnd = new Random();

            var dataSize = 16;
            while (dataSize <= 1 << 24)
            {
                var plaintext = new byte[dataSize];
                rnd.NextBytes(plaintext);

                var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(key);

                var nonce = new byte[Salsa20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var salsa20 = new Salsa20(key, 0);
                var cipher = new Salsa20CoreIntrinsics(salsa20);

                var ciphertext = new byte[plaintext.Length];
                cipher.Process(nonce, ciphertext, plaintext);

                var decrypted = new byte[plaintext.Length];
                cipher.Process(nonce, decrypted, ciphertext);

                decrypted.Should().Equal(plaintext);
                dataSize += 5 * dataSize / 11;
            }
        }

        [Fact]
        public void Salsa20IntrinsicsBlockWhenNonceLengthIsEmptyFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var salsa20 = new Salsa20(key, 0);
            var nonce = new byte[0];
            var block = new byte[Snuffle.BLOCK_SIZE_IN_BYTES];
            var core = new Salsa20CoreIntrinsics(salsa20);

            // Act & Assert
            var act = () => core.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void Salsa20IntrinsicsBlockWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var salsa20 = new Salsa20(key, 0);
            var nonce = new byte[salsa20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
            var block = new byte[Snuffle.BLOCK_SIZE_IN_BYTES];
            var core = new Salsa20CoreIntrinsics(salsa20);

            // Act & Assert
            var act = () => core.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void Salsa20IntrinsicsBlockWhenLengthIsInvalidFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var salsa20 = new Salsa20(key, 0);
            var nonce = new byte[salsa20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
            var block = new byte[0];
            var core = new Salsa20CoreIntrinsics(salsa20);

            // Act & Assert
            var act = () => core.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void Salsa20IntrinsicsBlockTestVector()
        {
            // Arrange
            var key = CryptoBytes.FromHexString("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".Replace(":", string.Empty));
            var nonce = CryptoBytes.FromHexString("00:00:00:09:00:00:00:4a".Replace(":", string.Empty));
            var counter = 1;

            // Act
            var salsa20 = new Salsa20(key, 1);
            var output = new byte[Snuffle.BLOCK_SIZE_IN_BYTES];
            var core = new Salsa20CoreIntrinsics(salsa20);
            core.ProcessKeyStreamBlock(nonce, counter, output);

            // Assert
            var expected = new uint[16]
            {
                3649387971u, 3432934094u, 2867581180u, 544842727u,
                3442094382u, 3233001746u, 2484653980u, 586338650u,
                3037335121u, 3388889956u, 1351682463u, 2284954070u,
                3021171268u, 2617586057u, 3288245149u, 2763695160u };

            output.ToUInt16Array().Should().Equal(expected);
        }

        public static IEnumerable<object[]> Salsa20TestData => ParseTestVectors(GetTestVector()).Select(d => new object[] { d });

        [Theory]
        [MemberData(nameof(Salsa20TestData))]
        public void Salsa20IntrinsicsProcessTestVectors(Salsa20TestVector test)
        {
            _output.WriteLine($"Salsa20 - {test.Name}");

            var input = new byte[512];
            var output = new byte[512];

            var cipher = new Salsa20(test.Key, 0);
            var core = new Salsa20CoreIntrinsics(cipher);
            core.Process(test.IV, output, input);

            ToBlock1(output).Should().Be(test.ExpectedBlock1);
            ToBlock4(output).Should().Be(test.ExpectedBlock4);
            ToBlock5(output).Should().Be(test.ExpectedBlock5);
            ToBlock8(output).Should().Be(test.ExpectedBlock8);
        }

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
        public void IntrinsicsCreateVariableLengthCiphers(int size)
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
            var lines = raw.Split(new[] { '\r', '\n' });

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

        private const string LongKeyStream = "A3D1F8292CAB0B2096AB2AA26FC59AAF3EE159B39FC6029EF160D82EC80FA110FF958AB802861180EC006F8C8450030024A2D7744BF564C1782F15DB6681144C65A730622A14AE9A4E95F753289A6D2DBBEE47B457B57DB75C009B287BF240EBE02890581E3628BDBCC9B79E93500CA15F6E10D4EBCAAFC2FB936AF2EC05BBCB1610036E840621D7CE53E4A06822D6073EA0FA8943EDFB70E45B4D2525AE4B616BD08B33F23A7E0B6CD501E80B8E80B7423E7C9D5D900AE2194AF0CF4A74D721534063D3F17BC7993B5B3EC20A373F933B43CEB6987934C1456521F098BA0CB1205109F534F80D4EA1767EA9DFC08BED97BE40C539DD37EC24EAE0C68AC1B56DD0189747A4B8278B1E0E5206EAE893C0E45C76751002F38924B8C9A036CFAB9E3D44C1E323BCE43F2C69EB8212994803C1D2AC00C3B8F97DA6D09F29B974E0DF4D6D36C9D2E88C2D7B73AB399C0920A2996A4727272339D991C6BF45CE63C2DEF3FC9C2625F87EA6268C196829BB1F7E659736AF4B0CC2A771FB0962B19005E53DD880879C052556312BA353B51C26D5F5949464EAECE15ACA240E339BF3C581E7D93D220B1C3C0DE87F65B4F340DAB924EB72072211C41B18770230A3A123619006BE5FD4ABAAFD2BFAD0F34D5FB491DEBEBF5CA9EC92D997B5A171482CC6E949C70759A0B8EC64D590B6FFF6500E8425C3AE4178C2EDE996C0003F6FA76A6D90F49D6D3D128C0DE82EA8C7C16415DDD07081940701677C32D5B5E3BB57A93315474C5B648D31AA7AE52FCD63BF22550900077FF5CF6A5F5148B285E34A57A3DA1BEB0662A20C23857CA8D5D1748F654F54F42F30CD413F408A0C7B31F57AD59E9F152DBDEEA3EA9C3DBB3517615735CFF0226E179C4A9149C6477A2903B338AE308300A86D91043E2AA437C5F2A77A49B547B05BD98CEBE49500FF367CE204157BB3EFD182A8A96FCC31025D4C948105F6762F22357446367B87A01FA3F954D52810CBE5C4EEB04C3AE827973E481F3C38EF14A6F0FE3FB2D89969D2CCB0DFB63D7366D91F29DDBF1EB90B136191745B8AC8B8F0AAEF4D3A1C763D63AED1E76CC7B920979CB8163C413273CA1A563C37B925A0251C9AD31363F978437D92437A0D250C7F221C00F2E13CF371554DF191ECDDB46C95659739A1CDC257A067D9251FE89EA328D313C4D7EF8E33614FFC4C615D3195CD6282D82633067C81E1F563DA307B14253CBF0492256A409E3007EB6A4A7BDA694E1FFA9B5106AB9868CC359B976441C7B362C03E501D8B3FBEF98771A41C4DA542DB8DA4761EA3792695288437DEAC50E7B6A62E6D00B7511A5DB0E567090ADDDFCF0521F6DD62F969D5BE89378DB127219C38931A0AEDBCE784C35D4215B09B1F96732615813753B67846E9505DF974F4B1ECDFBD0C850A9644D720884B80B4FE4CC08508A8A65D1C5F";
    }
}