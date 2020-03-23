namespace NaCl.Core.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Net.Http;
    using System.Security.Cryptography;
    using System.Text;

    using FluentAssertions;
    using Newtonsoft.Json;
    using Xunit;
    using Xunit.Abstractions;
    using Xunit.Categories;

    using Base;
    using Internal;
    using Vectors;

    [Category("CI")]
    public class XChaCha20Poly1305Test
    {
        private const string EXCEPTION_MESSAGE_NONCE_LENGTH = "*The nonce length in bytes must be 24.";
        private const string EXCEPTION_MESSAGE_TAG_LENGTH = "The tag length in bytes must be 16.";
        private readonly ITestOutputHelper _output;

        public XChaCha20Poly1305Test(ITestOutputHelper output) => _output = output;

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
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void EncryptWhenNonceIsEmptyFails()
        {
            // Arrange
            var nonce = new byte[0];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void EncryptWhenPlaintextAndCiphertextLengthDiffersFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            var plaintext = new byte[50];
            var ciphertext = new byte[40];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            act.Should().Throw<ArgumentException>().WithMessage("The plaintext parameter and the ciphertext do not have the same length.");
        }

        [Fact]
        public void EncryptWhenTagLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            act.Should().Throw<CryptographicException>().WithMessage(EXCEPTION_MESSAGE_TAG_LENGTH);
        }

        [Fact]
        public void EncryptWhenTagIsEmptyFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            var plaintext = new byte[50];
            var ciphertext = new byte[50];
            var tag = new byte[0];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            act.Should().Throw<CryptographicException>().WithMessage(EXCEPTION_MESSAGE_TAG_LENGTH);
        }

        [Fact]
        public void DecryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var plaintext = new byte[50];
            var ciphertext = new byte[50];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Decrypt(nonce, plaintext, tag, ciphertext, aad);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenNonceIsEmptyFails()
        {
            // Arrange
            var nonce = new byte[0];
            var plaintext = new byte[50];
            var ciphertext = new byte[50];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Decrypt(nonce, plaintext, tag, ciphertext, aad);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenPlaintextAndCiphertextLengthDiffersFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            var plaintext = new byte[50];
            var ciphertext = new byte[40];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Decrypt(nonce, plaintext, tag, ciphertext, aad);
            act.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
        }

        [Fact]
        public void DecryptWhenTagLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            var plaintext = new byte[50];
            var ciphertext = new byte[50];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Decrypt(nonce, plaintext, tag, ciphertext, aad);
            act.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
        }

        [Fact]
        public void DecryptWhenTagIsEmptyFails()
        {
            // Arrange
            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            var plaintext = new byte[50];
            var ciphertext = new byte[50];
            var tag = new byte[0];
            var aad = new byte[0];

            var aead = new XChaCha20Poly1305(new byte[Snuffle.KEY_SIZE_IN_BYTES]);

            // Act & Assert
            Action act = () => aead.Decrypt(nonce, plaintext, tag, ciphertext, aad);
            act.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
        }

        [Fact]
        public void EncryptDecryptTest()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(key);

            var aead = new XChaCha20Poly1305(key);
            for (var i = 0; i < 100; i++)
            {
                var message = new byte[100]; // rnd.Next(100)
                rnd.NextBytes(message);

                var aad = new byte[16]; // rnd.Next(16)
                rnd.NextBytes(aad);

                var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];

                var ciphertext = new byte[message.Length];
                aead.Encrypt(nonce, message, ciphertext, tag, aad);

                var decrypted = new byte[message.Length];
                aead.Decrypt(nonce, ciphertext, tag, decrypted, aad);

                decrypted.Should().Equal(message);
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

                var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(key);

                var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];

                var aead = new XChaCha20Poly1305(key);

                var ciphertext = new byte[plaintext.Length];
                aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);

                var decrypted = new byte[plaintext.Length];
                aead.Decrypt(nonce, ciphertext, tag, decrypted, aad);

                decrypted.Should().Equal(plaintext);
                dataSize += 5 * dataSize / 11;
            }
        }

        [Fact]
        public void ModifiedCiphertextFails()
        {
            var rnd = new Random();
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(key);

            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(nonce);

            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];

            var aad = new byte[16];
            rnd.NextBytes(aad);

            var message = new byte[32];
            rnd.NextBytes(message);

            var aead = new XChaCha20Poly1305(key);

            var ciphertext = new byte[message.Length];
            aead.Encrypt(nonce, message, ciphertext, tag, aad);

            // Flipping bits
            for (var b = 0; b < ciphertext.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[ciphertext.Length];
                    Array.Copy(ciphertext, modified, ciphertext.Length);

                    modified[b] ^= (byte)(1 << bit);

                    var decrypted = new byte[ciphertext.Length];
                    Action act = () => aead.Decrypt(nonce, modified, tag, decrypted, aad);
                    act.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
                }
            }

            // Truncate the message
            for (var length = 0; length < ciphertext.Length; length++)
            {
                var modified = new byte[length];
                Array.Copy(ciphertext, modified, length);

                var decrypted = new byte[modified.Length];
                Action act = () => aead.Decrypt(nonce, modified, tag, decrypted, aad);
                act.Should().Throw<Exception>();
            }

            // Modify AAD
            for (var b = 0; b < aad.Length; b++)
            {
                for (var bit = 0; bit < 8; bit++)
                {
                    var modified = new byte[aad.Length];
                    Array.Copy(aad, modified, aad.Length);

                    modified[b] ^= (byte)(1 << bit);

                    var decrypted = new byte[ciphertext.Length];
                    Action act = () => aead.Decrypt(nonce, ciphertext, tag, decrypted, modified);
                    act.Should().Throw<Exception>();
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
            RandomNumberGenerator.Fill(key);

            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(nonce);

            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];

            var aead = new XChaCha20Poly1305(key);
            var aad = new byte[0];

            for (var msgSize = 0; msgSize < 75; msgSize++)
            {
                var message = new byte[msgSize];
                rnd.NextBytes(message);

                var ciphertext = new byte[msgSize];
                var plaintext = new byte[msgSize];

                // encrypting with aad as a 0-length array
                aead.Encrypt(nonce, message, ciphertext, tag, aad);

                aead.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                message.Should().Equal(plaintext);

                aead.Decrypt(nonce, ciphertext, tag, plaintext, null);
                message.Should().Equal(plaintext);

                var badAad = new byte[] { 1, 2, 3 };
                Action badAadAct = () => aead.Decrypt(nonce, ciphertext, tag, plaintext, badAad);
                badAadAct.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);

                // encrypting with aad equal to null
                aead.Encrypt(nonce, message, ciphertext, tag, null);
                aead.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                message.Should().Equal(plaintext);

                aead.Decrypt(nonce, ciphertext, tag, plaintext, null);
                message.Should().Equal(plaintext);

                Action act = () => aead.Decrypt(nonce, ciphertext, tag, plaintext, badAad);
                act.Should().Throw<CryptographicException>().WithMessage(SnufflePoly1305.AEAD_EXCEPTION_INVALID_TAG);
            }
        }

        [Fact]
        public void RandomNonceTest()
        {
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(key);

            var nonce = new byte[XChaCha20.NONCE_SIZE_IN_BYTES];
            var tag = new byte[Poly1305.MAC_TAG_SIZE_IN_BYTES];

            var aead = new XChaCha20Poly1305(key);

            var message = Encoding.UTF8.GetBytes("This is a secret content!!");
            var aad = new byte[0];
            var ciphertexts = new HashSet<string>();
            var samples = 1 << 17;

            for (var i = 0; i < samples; i++)
            {
                RandomNumberGenerator.Fill(nonce);

                var ct = new byte[message.Length];
                aead.Encrypt(nonce, message, ct, tag, aad);
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

                var ct = new byte[test.PlainText.Length];
                aead.Encrypt(test.Nonce, test.PlainText, ct, test.Tag, test.Aad);
                ct.Should().BeEquivalentTo(test.CipherText);

                var output = new byte[test.CipherText.Length];
                aead.Decrypt(test.Nonce, test.CipherText, test.Tag, output, test.Aad);

                // Assert
                output.Should().Equal(test.PlainText);
            }
        }

        [Fact]
        public void WycheproofTestVectors()
        {
            var json = GetWycheproofTestVector();

            var vector = JsonConvert.DeserializeObject<WycheproofVector>(json); //Utf8Json.JsonSerializer.Deserialize<WycheproofVector>(json);

            var errors = 0;
            foreach (var group in vector.TestGroups)
            {
                foreach (var test in group.Tests)
                {
                    var id = $"TestCase {test.TcId}";
                    if (!string.IsNullOrEmpty(test.Comment))
                        id += $" ({test.Comment})";

                    var iv = CryptoBytes.FromHexString(test.Iv);
                    var key = CryptoBytes.FromHexString(test.Key);
                    var msg = CryptoBytes.FromHexString(test.Msg);
                    var aad = CryptoBytes.FromHexString(test.Aad);
                    var ct = CryptoBytes.FromHexString(test.Ct);
                    var tag = CryptoBytes.FromHexString(test.Tag);
                    //var ciphertext = iv.Concat(ct).Concat(tag).ToArray();

                    // Result is one of "valid", "invalid", "acceptable".
                    // "valid" are test vectors with matching plaintext, ciphertext and tag.
                    // "invalid" are test vectors with invalid parameters or invalid ciphertext and tag.
                    // "acceptable" are test vectors with weak parameters or legacy formats.

                    var result = test.Result;

                    try
                    {
                        var aead = new XChaCha20Poly1305(key);
                        //var decrypted = aead.Decrypt(ciphertext, aad);
                        var decrypted = new byte[msg.Length];
                        aead.Decrypt(iv, ct, tag, decrypted, aad);

                        if (test.Result == "invalid")
                        {
                            _output.WriteLine($"FAIL {id}: accepting invalid ciphertext, cleartext: {test.Msg}, decrypted: {CryptoBytes.ToHexStringLower(decrypted)}");
                            errors++;

                            continue;
                        }

                        if (!CryptoBytes.ConstantTimeEquals(msg, decrypted))
                        {
                            _output.WriteLine($"FAIL {id}: incorrect decryption, result: {CryptoBytes.ToHexStringLower(decrypted)}, expected: {test.Msg}");
                            errors++;
                        }
                    }
                    catch (Exception ex)
                    {
                        if (test.Result == "valid")
                        {
                            _output.WriteLine($"FAIL {id}: cannot decrypt, exception: {ex}");
                            errors++;
                        }
                    }
                }
            }

            errors.Should().Be(0);
        }

        private string GetWycheproofTestVector()
        {
            try
            {
                using var client = new HttpClient();
                return client.GetStringAsync("https://github.com/google/wycheproof/raw/master/testvectors/xchacha20_poly1305_test.json").Result;
            }
            catch (Exception)
            {
                return File.ReadAllText(@"Vectors\xchacha20_poly1305_test.json");
            }
        }
    }
}
