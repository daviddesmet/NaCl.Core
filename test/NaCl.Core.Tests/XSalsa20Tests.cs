namespace NaCl.Core.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    using FluentAssertions;
    using Xunit;
    using Xunit.Abstractions;
    using Xunit.Categories;

    using Base;

    [Category("CI")]
    public class XSalsa20Tests
    {
        private readonly ITestOutputHelper _output;

        public XSalsa20Tests(ITestOutputHelper output) => _output = output;

        private const string EXCEPTION_MESSAGE_NONCE_LENGTH = "*The nonce length in bytes must be 24.";

        [Fact]
        public void CreateInstanceWhenKeyLengthIsInvalidFails()
        {
            // Arrange, Act & Assert
            Action act = () => new XSalsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()], 0);
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
            var cipher = new XSalsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

            // Act
            var act = () => cipher.Encrypt(new byte[plaintextLen], new byte[cipher.NonceSizeInBytes], new byte[ciphertextLen]);

            // Assert
            act.Should().Throw<ArgumentException>().WithMessage("The plaintext parameter and the ciphertext do not have the same length.");
        }

        [Fact]
        public void EncryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[XSalsa20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];

            var cipher = new XSalsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

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

            var cipher = new XSalsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

            // Act & Assert
            var act = () => cipher.Encrypt(plaintext, nonce, ciphertext);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[XSalsa20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];

            var cipher = new XSalsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

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

            var cipher = new XSalsa20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

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
            var cipher = new XSalsa20(key, 0);
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

            var nonce = new byte[XSalsa20.NONCE_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(nonce);

            var expected = Encoding.UTF8.GetBytes("This is a secret content!!");

            var cipher = new XSalsa20(key, 0);

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
            var nonce = new byte[XSalsa20.NONCE_SIZE_IN_BYTES];

            for (var i = 0; i < 64; i++)
            {
                RandomNumberGenerator.Fill(key);
                RandomNumberGenerator.Fill(nonce);

                var cipher = new XSalsa20(key, 0);

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

                var nonce = new byte[XSalsa20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var cipher = new XSalsa20(key, 0);

                var ciphertext = new byte[plaintext.Length];
                cipher.Encrypt(plaintext, nonce, ciphertext);

                var decrypted = new byte[plaintext.Length];
                cipher.Decrypt(ciphertext, nonce, decrypted);

                decrypted.Should().Equal(plaintext);
                dataSize += 5 * dataSize / 11;
            }
        }

        [Fact]
        public void XSalsa20BlockWhenNonceLengthIsEmptyFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var xsalsa20 = new XSalsa20(key, 0);
            var nonce = new byte[0];
            var block = new byte[XSalsa20.BLOCK_SIZE_IN_BYTES];

            // Act & Assert
            var act = () => xsalsa20.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void XSalsa20BlockWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var xsalsa20 = new XSalsa20(key, 0);
            var nonce = new byte[xsalsa20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
            var block = new byte[XSalsa20.BLOCK_SIZE_IN_BYTES];

            // Act & Assert
            var act = () => xsalsa20.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void XSalsa20BlockWhenLengthIsInvalidFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var xsalsa20 = new XSalsa20(key, 0);
            var nonce = new byte[xsalsa20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
            var block = new byte[0];

            // Act & Assert
            var act = () => xsalsa20.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void HSalsa20TestVector1()
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

            var cipher = new XSalsa20(shared);

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
        public void HSalsa20TestVector2()
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

            var cipher = new XSalsa20(firstKey);

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
        public void HSalsa20TestVector3()
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

            var cipher = new XSalsa20(k);

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

        // TODO: Add test vectors
    }
}