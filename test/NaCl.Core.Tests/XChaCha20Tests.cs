namespace NaCl.Core.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;

    using FluentAssertions;
    using Xunit;
    using Xunit.Categories;

    using Base;
    using Internal;
    using Vectors;

    [Category("CI")]
    public class XChaCha20Tests
    {
        private const string EXCEPTION_MESSAGE_NONCE_LENGTH = "*The nonce length in bytes must be 24.";

        [Fact]
        public void CreateInstanceWhenKeyLengthIsInvalidFails()
        {
            // Arrange, Act & Assert
            Action act = () => new XChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()], 0);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void EncryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];

            var cipher = new XChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

            // Act & Assert
            Action act = () => cipher.Encrypt(plaintext, nonce, ciphertext);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void EncryptWhenNonceIsEmptyFails()
        {
            // Arrange
            var nonce = new byte[0];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];

            var cipher = new XChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

            // Act & Assert
            Action act = () => cipher.Encrypt(plaintext, nonce, ciphertext);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];

            var cipher = new XChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

            // Act & Assert
            Action act = () => cipher.Decrypt(ciphertext, nonce, plaintext);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenNonceIsEmptyFails()
        {
            // Arrange
            var nonce = new byte[0];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];

            var cipher = new XChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

            // Act & Assert
            Action act = () => cipher.Decrypt(ciphertext, nonce, plaintext);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenCiphertextIsTooShortFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(key);

            // Act
            var cipher = new XChaCha20(key, 0);
            Action act = () => cipher.Decrypt(new byte[2]);

            // Assert
            act.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void EncryptDecryptNBlocksTest()
        {
            // Arrange
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            for (var i = 0; i < 64; i++)
            {
                RandomNumberGenerator.Fill(key);

                var cipher = new XChaCha20(key, 0);

                for (var j = 0; j < 64; j++)
                {
                    var expected = new byte[rnd.Next(300)];
                    rnd.NextBytes(expected);

                    // Act
                    var output = cipher.Encrypt(expected);
                    var plaintext = cipher.Decrypt(output);

                    // Assert
                    plaintext.Should().Equal(expected);
                }
            }
        }

        [Fact]
        public void EncryptDecryptNBlocksWithNonceTest()
        {
            // Arrange
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            for (var i = 0; i < 64; i++)
            {
                RandomNumberGenerator.Fill(key);

                var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var cipher = new XChaCha20(key, 0);

                for (var j = 0; j < 64; j++)
                {
                    var expected = new byte[rnd.Next(300)];
                    rnd.NextBytes(expected);

                    // Act
                    var ciphertext = cipher.Encrypt(expected, nonce);
                    var plaintext = cipher.Decrypt(ciphertext, nonce);

                    // Assert
                    plaintext.Should().Equal(expected);
                }
            }
        }

        [Fact]
        public void EncryptDecryptNBlocksWithDestinationBufferTest()
        {
            // Arrange
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            for (var i = 0; i < 64; i++)
            {
                RandomNumberGenerator.Fill(key);

                var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var cipher = new XChaCha20(key, 0);

                for (var j = 0; j < 64; j++)
                {
                    var expected = new byte[rnd.Next(300)];
                    rnd.NextBytes(expected);

                    // Act
                    var ciphertext = new byte[expected.Length];
                    cipher.Encrypt(expected, nonce, ciphertext);

                    var plaintext = new byte[expected.Length];
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

                var cipher = new XChaCha20(key, 0);

                var ciphertext = cipher.Encrypt(plaintext);
                var decrypted = cipher.Decrypt(ciphertext);

                decrypted.Should().Equal(plaintext);
                dataSize += 5 * dataSize / 11;
            }
        }

        [Fact]
        public void EncryptDecryptLongMessagesWithNonceTest()
        {
            var rnd = new Random();

            var dataSize = 16;
            while (dataSize <= (1 << 24))
            {
                var plaintext = new byte[dataSize];
                rnd.NextBytes(plaintext);

                var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(key);

                var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var cipher = new XChaCha20(key, 0);

                var ciphertext = cipher.Encrypt(plaintext, nonce);
                var decrypted = cipher.Decrypt(ciphertext, nonce);

                decrypted.Should().Equal(plaintext);
                dataSize += 5 * dataSize / 11;
            }
        }

        [Fact]
        public void EncryptDecryptLongMessagesWithDestinationBufferTest()
        {
            var rnd = new Random();

            var dataSize = 16;
            while (dataSize <= (1 << 24))
            {
                var plaintext = new byte[dataSize];
                rnd.NextBytes(plaintext);

                var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(key);

                var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var cipher = new XChaCha20(key, 0);

                var ciphertext = new byte[plaintext.Length];
                cipher.Encrypt(plaintext, nonce, ciphertext);

                var decrypted = new byte[plaintext.Length];
                cipher.Decrypt(ciphertext, nonce, decrypted);

                decrypted.Should().Equal(plaintext);
                dataSize += 5 * dataSize / 11;
            }
        }

        [Fact]
        public void XChaCha20BlockWhenNonceLengthIsEmptyFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var cipher = new XChaCha20(key, 0);
            var nonce = new byte[0];
            var block = new byte[Snuffle.BLOCK_SIZE_IN_BYTES];

            // Act & Assert
            Action act = () => cipher.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void XChaCha20BlockWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var cipher = new XChaCha20(key, 0);
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var block = new byte[Snuffle.BLOCK_SIZE_IN_BYTES];

            // Act & Assert
            Action act = () => cipher.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void XChaCha20BlockWhenLengthIsInvalidFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var cipher = new XChaCha20(key, 0);
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var block = new byte[0];

            // Act & Assert
            Action act = () => cipher.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void HChaCha20TestVectors()
        {
            // Arrange
            foreach (var test in HChaCha20TestVector.HChaCha20TestVectors)
            {
                var cipher = new XChaCha20(test.Key, 0);

                // Act
                var output = new byte[Snuffle.KEY_SIZE_IN_BYTES];
                cipher.HChaCha20(output, test.Input);

                // Assert
                output.Should().Equal(test.Output);
            }
        }

        [Fact]
        public void XChaCha20TestVectors()
        {
            // From libsodium's test/default/xchacha20.c (tv_stream_xchacha20) and https://tools.ietf.org/html/draft-arciszewski-xchacha-00.

            // Arrange
            foreach (var test in XChaCha20TestVector.XChaCha20TestVectors)
            {
                // Act
                var cipher = new XChaCha20(test.Key, 0);

                // We do test all method overloads
                var output1 = cipher.Decrypt(CryptoBytes.Combine(test.Nonce, test.CipherText));
                var output2 = cipher.Decrypt(test.CipherText, test.Nonce);
                var output3 = new byte[test.CipherText.Length];
                cipher.Decrypt(test.CipherText, test.Nonce, output3);

                // Assert
                output1.Should().Equal(test.PlainText);
                output2.Should().Equal(test.PlainText);
                output3.Should().Equal(test.PlainText);
            }
        }

        [Fact]
        public void HChaCha20StateTestVector()
        {
            // https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03#section-2.2.1

            // Arrange
            var key = CryptoBytes.FromHexString("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".Replace(":", string.Empty));
            var nonce = CryptoBytes.FromHexString("00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27".Replace(":", string.Empty));
            var cipher = new XChaCha20(key, 0);

            // Act
            var initialState = new uint[16];
            cipher.HChaCha20InitialState(initialState, nonce);

            // Assert
            var expectedInitialState = new uint[]
            {
                0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
                0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
                0x09000000, 0x4a000000, 0x00000000, 0x27594131
            };

            initialState.Should().BeEquivalentTo(expectedInitialState);
        }

        [Fact]
        public void HChaCha20BlockTestVector()
        {
            // https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03#section-2.2.1

            // Arrange
            var key = CryptoBytes.FromHexString("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".Replace(":", string.Empty));
            var nonce = CryptoBytes.FromHexString("00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27".Replace(":", string.Empty));
            var cipher = new XChaCha20(key, 0);

            // Act
            var subKey = new byte[32];
            cipher.HChaCha20(subKey, nonce);
            var state = subKey.ToUInt16Array();
            //var stateHex = CryptoBytes.ToHexStringLower(subKey.ToArray());

            // Assert
            // HChaCha20 returns only the first and last rows
            var expectedState = new uint[]
            {
                0x423b4182, 0xfe7bb227, 0x50420ed3, 0x737d878a,
                //0x0aa76448, 0x7954cdf3, 0x846acd37, 0x7b3c58ad,
                //0x77e35583, 0x83e77c12, 0xe0076a2d, 0xbc6cd0e5,
                0xd5e4f9a0, 0x53a8748a, 0x13c42ec1, 0xdcecd326
            };

            // Same as above but in HEX
            //var expectedStateHex = "82413b4" + "227b27bfe" + "d30e4250" + "8a877d73"
            //                     + "a0f9e4d" + "58a74a853" + "c12ec413" + "26d3ecdc";

            state.Should().BeEquivalentTo(expectedState);
            //stateHex.Should().Be(expectedStateHex);
        }
    }
}
