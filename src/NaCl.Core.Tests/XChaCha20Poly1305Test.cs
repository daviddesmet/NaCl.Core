namespace NaCl.Core.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;

    using NUnit.Framework;

    using Base;
    using Internal;
    using Vectors;

    [TestFixture]
    public class XChaCha20Poly1305Test
    {
        private const string EXCEPTION_MESSAGE_NONCE_LENGTH = "The nonce length in bytes must be 24.";

        [Test]
        public void CreateInstanceWhenKeyLengthIsInvalidFails()
        {
            // Arrange, Act & Assert
            Assert.Throws<CryptographicException>(() => new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()]));
        }

        [Test]
        public void EncryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange, Act & Assert
            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);
            Assert.Throws<CryptographicException>(() => aead.Encrypt(new byte[0], new byte[0], new byte[24 + TestHelpers.ReturnRandomPositiveNegative()]), EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Test]
        public void DecryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange, Act & Assert
            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);
            Assert.Throws<CryptographicException>(() => aead.Decrypt(new byte[50], new byte[0], new byte[24 + TestHelpers.ReturnRandomPositiveNegative()]), EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Test]
        public void DecryptWhenCiphertextIsTooShortFails()
        {
            // Arrange & Act
            var cipher = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Assert
            Assert.Throws<CryptographicException>(() => cipher.Decrypt(new byte[27], new byte[1]));
        }

        [Test]
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

                //Assert.AreEqual(message, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted));
            }
        }

        [Test]
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

                //Assert.AreEqual(message, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted));
            }
        }

        [Test]
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

                //Assert.AreEqual(plaintext, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(plaintext, decrypted));
                dataSize += 5 * dataSize / 11;
            }
        }

        [Test]
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

                //Assert.AreEqual(plaintext, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(plaintext, decrypted));
                dataSize += 5 * dataSize / 11;
            }
        }

        [Test]
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

                    Assert.Throws<CryptographicException>(() => aead.Decrypt(modified, aad), SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
                }
            }

            // Truncate the message
            for (var length = 0; length < ciphertext.Length; length++)
            {
                var modified = new byte[length];
                Array.Copy(ciphertext, modified, length);

                Assert.Throws<CryptographicException>(() => aead.Decrypt(modified, aad), SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
            }

            // Modify AAD
            for (var b = 0; b < aad.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[aad.Length];
                    Array.Copy(aad, modified, aad.Length);

                    modified[b] ^= (byte)(1 << bit);

                    Assert.Throws<CryptographicException>(() => aead.Decrypt(modified, aad), SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
                }
            }
        }

        [Test]
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

        [Test]
        public void EmptyAssociatedDataFails()
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
                //Assert.AreEqual(message, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted));

                var decrypted2 = aead.Decrypt(ciphertext, null);
                //Assert.AreEqual(message, decrypted2);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted2));

                var badAad = new byte[] { 1, 2, 3 };
                Assert.Throws<CryptographicException>(() => aead.Decrypt(ciphertext, badAad), SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);

                // encrypting with aad equal to null
                ciphertext = aead.Encrypt(message, null);
                decrypted = aead.Decrypt(ciphertext, aad);
                //Assert.AreEqual(message, decrypted);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted));

                decrypted2 = aead.Decrypt(ciphertext, null);
                //Assert.AreEqual(message, decrypted2);
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(message, decrypted2));

                Assert.Throws<CryptographicException>(() => aead.Decrypt(ciphertext, badAad), SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
            }
        }

        [Test]
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

                Assert.IsFalse(ciphertexts.Contains(ctHex));
                ciphertexts.Add(ctHex);
            }

            Assert.AreEqual(samples, ciphertexts.Count);
        }

        [Test]
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
                //Assert.That(output, Is.EqualTo(test.PlainText));
                Assert.IsTrue(CryptoBytes.ConstantTimeEquals(test.PlainText, output));
            }
        }
    }
}
