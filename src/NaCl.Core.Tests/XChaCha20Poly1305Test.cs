namespace NaCl.Core.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;

    using FluentAssertions;
    using Newtonsoft.Json;
    using Xunit;
    using Xunit.Categories;

    using Base;
    using Internal;
    using Vectors;

    [Category("CI")]
    public class XChaCha20Poly1305Test
    {
        private const string EXCEPTION_MESSAGE_NONCE_LENGTH = "*The nonce length in bytes must be 24.";

        [Fact]
        public void CreateInstanceWhenKeyLengthIsInvalidFails()
        {
            // Arrange, Act & Assert
            Action act = () => new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()]);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void EncryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Encrypt(new byte[0], new byte[0], new byte[24 + TestHelpers.ReturnRandomPositiveNegative()]);
            act.Should().Throw<CryptographicException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void EncryptWhenNonceIsEmptyFails()
        {
            // Arrange
            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Encrypt(new byte[0], new byte[0], new byte[0]);
            act.Should().Throw<CryptographicException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Decrypt(new byte[50], new byte[0], new byte[24 + TestHelpers.ReturnRandomPositiveNegative()]);
            act.Should().Throw<CryptographicException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenNonceIsEmptyFails()
        {
            // Arrange
            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Decrypt(new byte[50], new byte[0], new byte[0]);
            act.Should().Throw<CryptographicException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenCiphertextIsTooShortFails()
        {
            // Arrange
            var cipher = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => cipher.Decrypt(new byte[27], new byte[1]);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void DecryptWithNonceWhenCiphertextIsTooShortFails()
        {
            // Arrange
            var cipher = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => cipher.Decrypt(new byte[27], new byte[1], new byte[1]);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void EncryptDecryptTest()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new XChaCha20Poly1305(key);
            for (var i = 0; i < 100; i++)
            {
                var message = new byte[100]; // rnd.Next(100)
                rnd.NextBytes(message);

                var aad = new byte[16]; // rnd.Next(16)
                rnd.NextBytes(aad);

                var ciphertext = aead.Encrypt(message, aad);
                var decrypted = aead.Decrypt(ciphertext, aad);

                CryptoBytes.ConstantTimeEquals(message, decrypted).Should().BeTrue();
            }
        }

        [Fact]
        public void EncryptDecryptWithNonceTest()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new XChaCha20Poly1305(key);
            for (var i = 0; i < 100; i++)
            {
                var message = new byte[100];
                rnd.NextBytes(message);

                var aad = new byte[16];
                rnd.NextBytes(aad);

                var nonce = new byte[24];
                rnd.NextBytes(nonce);

                var ciphertext = aead.Encrypt(message, aad, nonce);
                var decrypted = aead.Decrypt(ciphertext, aad, nonce);

                CryptoBytes.ConstantTimeEquals(message, decrypted).Should().BeTrue();
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

                var aad = new byte[dataSize / 3];
                rnd.NextBytes(aad);

                var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
                rnd.NextBytes(key);

                var aead = new XChaCha20Poly1305(key);
                var ciphertext = aead.Encrypt(plaintext, aad);
                var decrypted = aead.Decrypt(ciphertext, aad);

                CryptoBytes.ConstantTimeEquals(plaintext, decrypted).Should().BeTrue();
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

                var aad = new byte[dataSize / 3];
                rnd.NextBytes(aad);

                var nonce = new byte[24];
                rnd.NextBytes(nonce);

                var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
                rnd.NextBytes(key);

                var aead = new XChaCha20Poly1305(key);
                var ciphertext = aead.Encrypt(plaintext, aad, nonce);
                var decrypted = aead.Decrypt(ciphertext, aad, nonce);

                CryptoBytes.ConstantTimeEquals(plaintext, decrypted).Should().BeTrue();
                dataSize += 5 * dataSize / 11;
            }
        }

        [Fact]
        public void ModifiedCiphertextFails()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aad = new byte[16];
            rnd.NextBytes(aad);

            var message = new byte[32];
            rnd.NextBytes(message);

            var aead = new XChaCha20Poly1305(key);
            var ciphertext = aead.Encrypt(message, aad);

            // Flipping bits
            for (var b = 0; b < ciphertext.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[ciphertext.Length];
                    Array.Copy(ciphertext, modified, ciphertext.Length);

                    modified[b] ^= (byte)(1 << bit);

                    Action act = () => aead.Decrypt(modified, aad);
                    act.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
                }
            }

            // Truncate the message
            for (var length = 0; length < ciphertext.Length; length++)
            {
                var modified = new byte[length];
                Array.Copy(ciphertext, modified, length);

                Action act = () => aead.Decrypt(modified, aad);
                act.Should().Throw<CryptographicException>();
            }

            // Modify AAD
            for (var b = 0; b < aad.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[aad.Length];
                    Array.Copy(aad, modified, aad.Length);

                    modified[b] ^= (byte)(1 << bit);

                    Action act = () => aead.Decrypt(modified, aad);
                    act.Should().Throw<CryptographicException>();
                }
            }
        }

        /*
        [Fact]
        public void NullPlaintextOrCiphertextFails()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new XChaCha20Poly1305(key);
            var aad = new byte[] { 1, 2, 3 };

            Assert.Throws<ArgumentNullException>(() => aead.Encrypt(null, aad));
            Assert.Throws<ArgumentNullException>(() => aead.Encrypt(null, null));
            Assert.Throws<ArgumentNullException>(() => aead.Decrypt(null, aad));
            Assert.Throws<ArgumentNullException>(() => aead.Decrypt(null, null));
        }
        */

        [Fact]
        public void ModifiedAssociatedDataFails()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new XChaCha20Poly1305(key);
            var aad = new byte[0];

            for (var msgSize = 0; msgSize < 75; msgSize++)
            {
                var message = new byte[msgSize];
                rnd.NextBytes(message);

                // encrypting with aad as a 0-length array
                var ciphertext = aead.Encrypt(message, aad);
                var decrypted = aead.Decrypt(ciphertext, aad);
                CryptoBytes.ConstantTimeEquals(message, decrypted).Should().BeTrue();

                var decrypted2 = aead.Decrypt(ciphertext, null);
                CryptoBytes.ConstantTimeEquals(message, decrypted2).Should().BeTrue();

                var badAad = new byte[] { 1, 2, 3 };
                Action badAadAct = () => aead.Decrypt(ciphertext, badAad);
                badAadAct.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);

                // encrypting with aad equal to null
                ciphertext = aead.Encrypt(message, null);
                decrypted = aead.Decrypt(ciphertext, aad);
                CryptoBytes.ConstantTimeEquals(message, decrypted).Should().BeTrue();

                decrypted2 = aead.Decrypt(ciphertext, null);
                CryptoBytes.ConstantTimeEquals(message, decrypted2).Should().BeTrue();

                Action act = () => aead.Decrypt(ciphertext, badAad);
                act.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
            }
        }

        [Fact]
        public void RandomNonceTest()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            rnd.NextBytes(key);

            var aead = new XChaCha20Poly1305(key);

            var message = new byte[0];
            var aad = new byte[0];
            var ciphertexts = new HashSet<string>();
            var samples = 1 << 17;

            for (var i = 0; i < samples; i++)
            {
                var ct = aead.Encrypt(message, aad);
                var ctHex = CryptoBytes.ToHexStringLower(ct);

                ciphertexts.Contains(ctHex).Should().BeFalse();
                ciphertexts.Add(ctHex);
            }

            ciphertexts.Count.Should().Be(samples);
        }

        [Fact]
        public void XChaCha20Poly1305TestVectors()
        {
            // From libsodium's test/default/aead_xchacha20poly1305.c and https://tools.ietf.org/html/draft-arciszewski-xchacha-01.

            // Arrange
            foreach (var test in XChaCha20Poly1305TestVector.TestVectors)
            {
                // Act
                var aead = new XChaCha20Poly1305(test.Key);

                //var message = aead.Decrypt(CryptoBytes.Combine(test.CipherText, test.Tag), test.Aad, test.Nonce); // same as below...
                var output = aead.Decrypt(CryptoBytes.Combine(test.Nonce, test.CipherText, test.Tag), test.Aad);

                // Assert
                CryptoBytes.ConstantTimeEquals(test.PlainText, output).Should().BeTrue();
            }
        }
    }
}
