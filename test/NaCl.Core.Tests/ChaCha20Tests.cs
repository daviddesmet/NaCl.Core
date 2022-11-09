﻿namespace NaCl.Core.Tests
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    using FluentAssertions;
    using Xunit;
    using Xunit.Categories;

    using Base;
    using Internal;
    using Vectors;

    [Category("CI")]
    public class ChaCha20Tests
    {
        private const string EXCEPTION_MESSAGE_NONCE_LENGTH = "*The nonce length in bytes must be 12.";

        [Fact]
        public void CreateInstanceWhenKeyLengthIsInvalidFails()
        {
            // Arrange, Act & Assert
            Action act = () => new ChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()], 0);
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
            var cipher = new ChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

            // Act
            var act = () => cipher.Encrypt(new byte[plaintextLen], new byte[cipher.NonceSizeInBytes], new byte[ciphertextLen]);

            // Assert
            act.Should().Throw<ArgumentException>().WithMessage("The plaintext parameter and the ciphertext do not have the same length.");
        }

        [Fact]
        public void EncryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[ChaCha20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];

            var cipher = new ChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

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

            var cipher = new ChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

            // Act & Assert
            var act = () => cipher.Encrypt(plaintext, nonce, ciphertext);
            act.Should().Throw<ArgumentException>().WithMessage(EXCEPTION_MESSAGE_NONCE_LENGTH);
        }

        [Fact]
        public void DecryptWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var nonce = new byte[ChaCha20.NONCE_SIZE_IN_BYTES + TestHelpers.ReturnRandomPositiveNegative()];
            var plaintext = new byte[0];
            var ciphertext = new byte[0];

            var cipher = new ChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

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

            var cipher = new ChaCha20(new byte[Snuffle.KEY_SIZE_IN_BYTES], 0);

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
            var cipher = new ChaCha20(key, 0);
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

            var nonce = new byte[ChaCha20.NONCE_SIZE_IN_BYTES];
            RandomNumberGenerator.Fill(nonce);

            var expected = Encoding.UTF8.GetBytes("This is a secret content!!");

            var cipher = new ChaCha20(key, 0);

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
            var nonce = new byte[ChaCha20.NONCE_SIZE_IN_BYTES];

            for (var i = 0; i < 64; i++)
            {
                RandomNumberGenerator.Fill(key);
                RandomNumberGenerator.Fill(nonce);

                var cipher = new ChaCha20(key, 0);

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

                var nonce = new byte[ChaCha20.NONCE_SIZE_IN_BYTES];
                RandomNumberGenerator.Fill(nonce);

                var cipher = new ChaCha20(key, 0);

                var ciphertext = new byte[plaintext.Length];
                cipher.Encrypt(plaintext, nonce, ciphertext);

                var decrypted = new byte[plaintext.Length];
                cipher.Decrypt(ciphertext, nonce, decrypted);

                decrypted.Should().Equal(plaintext);
                dataSize += 5 * dataSize / 11;
            }
        }

        [Fact]
        public void QuarterRoundTest()
        {
            // https://tools.ietf.org/html/rfc8439#section-2.1.1

            // Arrange
            var x = new uint[] { 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567 };

            // Act
            ChaCha20Base.QuarterRound(ref x[0], ref x[1], ref x[2], ref x[3]);

            // Assert
            x.Should().Equal(new uint[] { 0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb });
        }

        [Fact]
        public void QuarterRound16Test()
        {
            // https://tools.ietf.org/html/rfc8439#section-2.2.1

            // Arrange
            var x = new uint[] { 0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320 };

            // Act
            ChaCha20Base.QuarterRound(ref x[2], ref x[7], ref x[8], ref x[13]);

            // Assert
            x.Should().Equal(new uint[] { 0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320 });
        }

        [Fact]
        public void ChaCha20BlockWhenNonceLengthIsEmptyFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var chacha20 = new ChaCha20(key, 0);
            var nonce = new byte[0];
            var block = new byte[ChaCha20.BLOCK_SIZE_IN_BYTES];

            // Act & Assert
            var act = () => chacha20.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void ChaCha20BlockWhenNonceLengthIsInvalidFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var chacha20 = new ChaCha20(key, 0);
            var nonce = new byte[chacha20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
            var block = new byte[ChaCha20.BLOCK_SIZE_IN_BYTES];

            // Act & Assert
            var act = () => chacha20.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void ChaCha20BlockWhenLengthIsInvalidFails()
        {
            // Arrange
            var key = new byte[Snuffle.KEY_SIZE_IN_BYTES];

            var chacha20 = new ChaCha20(key, 0);
            var nonce = new byte[chacha20.NonceSizeInBytes + TestHelpers.ReturnRandomPositiveNegative()];
            var block = new byte[0];

            // Act & Assert
            var act = () => chacha20.ProcessKeyStreamBlock(nonce, 0, block);
            act.Should().Throw<CryptographicException>();
        }

        [Fact]
        public void ChaCha20BlockTestVector()
        {
            // https://tools.ietf.org/html/rfc8439#section-2.3.2

            // Arrange
            var key = CryptoBytes.FromHexString("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f".Replace(":", string.Empty));
            var nonce = CryptoBytes.FromHexString("00:00:00:09:00:00:00:4a:00:00:00:00".Replace(":", string.Empty));
            var counter = 1;

            // Act
            var chacha20 = new ChaCha20(key, 1);
            var output = new byte[ChaCha20.BLOCK_SIZE_IN_BYTES];
            chacha20.ProcessKeyStreamBlock(nonce, counter, output);

            // Assert
            var expected = new uint[16]
            {
                0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
                0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
                0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
                0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
            };

            output.ToUInt16Array().Should().Equal(expected);
        }

        [Fact]
        public void ChaCha20TestVector()
        {
            // https://tools.ietf.org/html/rfc8439#section-2.4.2

            // Arrange
            foreach (var test in Rfc8439TestVector.Rfc8439TestVectors)
            {
                // Act
                var cipher = new ChaCha20(test.Key, test.InitialCounter);

                var output = new byte[test.CipherText.Length];
                cipher.Decrypt(test.CipherText, test.Nonce, output);

                // Assert
                output.Should().Equal(test.PlainText);
            }
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
        public void CreateVariableLengthCiphers(int size)
        {
            var input = new byte[size];
            var output = new byte[size];

            var nonce = new byte[12];
            Array.Fill(nonce, (byte)2);

            var key = new byte[32];
            Array.Fill(key, (byte)1);

            var cipher = new ChaCha20(key, 0);
            cipher.Encrypt(input, nonce, output);
            var value = Convert.ToHexString(output);

            value.Should().Be(LongKeyStream[..(size*2)]);
        }

        [Fact]
        public void ChaCha20TestVectorTC8()
        {
            // TC8: key: 'All your base are belong to us!, IV: 'IETF2013'
            // Test vector TC8 from RFC draft by J. Strombergson
            // https://tools.ietf.org/html/draft-strombergson-chacha-test-vectors-01

            // Arrange
            var key = new byte[32]
            {
                0xC4, 0x6E, 0xC1, 0xB1, 0x8C, 0xE8, 0xA8, 0x78,
                0x72, 0x5A, 0x37, 0xE7, 0x80, 0xDF, 0xB7, 0x35,
                0x1F, 0x68, 0xED, 0x2E, 0x19, 0x4C, 0x79, 0xFB,
                0xC6, 0xAE, 0xBE, 0xE1, 0xA6, 0x67, 0x97, 0x5D
            };

            // The first 4 bytes are set to zero and a large counter
            // is used; this makes the RFC 8439 version of ChaCha20
            // compatible with the original specification by D. J. Bernstein.
            var nonce = new byte[12] { 0x00, 0x00, 0x00, 0x00,
                0x1A, 0xDA, 0x31, 0xD5, 0xCF, 0x68, 0x82, 0x21
            };

            // Act
            var cipher = new ChaCha20(key, 0);
            var block0 = new byte[ChaCha20.BLOCK_SIZE_IN_BYTES];
            var block1 = new byte[ChaCha20.BLOCK_SIZE_IN_BYTES];
            cipher.ProcessKeyStreamBlock(nonce, 0, block0);
            cipher.ProcessKeyStreamBlock(nonce, 1, block1);

            // Assert
            var expected = new byte[128]
            {
                0xF6, 0x3A, 0x89, 0xB7, 0x5C, 0x22, 0x71, 0xF9,
                0x36, 0x88, 0x16, 0x54, 0x2B, 0xA5, 0x2F, 0x06,
                0xED, 0x49, 0x24, 0x17, 0x92, 0x30, 0x2B, 0x00,
                0xB5, 0xE8, 0xF8, 0x0A, 0xE9, 0xA4, 0x73, 0xAF,
                0xC2, 0x5B, 0x21, 0x8F, 0x51, 0x9A, 0xF0, 0xFD,
                0xD4, 0x06, 0x36, 0x2E, 0x8D, 0x69, 0xDE, 0x7F,
                0x54, 0xC6, 0x04, 0xA6, 0xE0, 0x0F, 0x35, 0x3F,
                0x11, 0x0F, 0x77, 0x1B, 0xDC, 0xA8, 0xAB, 0x92,

                0xE5, 0xFB, 0xC3, 0x4E, 0x60, 0xA1, 0xD9, 0xA9,
                0xDB, 0x17, 0x34, 0x5B, 0x0A, 0x40, 0x27, 0x36,
                0x85, 0x3B, 0xF9, 0x10, 0xB0, 0x60, 0xBD, 0xF1,
                0xF8, 0x97, 0xB6, 0x29, 0x0F, 0x01, 0xD1, 0x38,
                0xAE, 0x2C, 0x4C, 0x90, 0x22, 0x5B, 0xA9, 0xEA,
                0x14, 0xD5, 0x18, 0xF5, 0x59, 0x29, 0xDE, 0xA0,
                0x98, 0xCA, 0x7A, 0x6C, 0xCF, 0xE6, 0x12, 0x27,
                0x05, 0x3C, 0x84, 0xE4, 0x9A, 0x4A, 0x33, 0x32
            };

            CryptoBytes.Combine(block0, block1).Should().Equal(expected);
        }

        private const string LongKeyStream = "06E1F8D66AC5C75181F3E5ED9FA16AA909A1FB57A4A9B0110C84FCDC0D710880072A4342AF88DEC0138DAF141A3F471C01E77C1FDA90999496D601A36A8C0412E61CF22E8DA3E8DA712DE9F9D38BE4298CB36C0D83AA7DD314841BBDF59644DCD313F9F53B0E06B9D6CB3F0788CE2EE78993D9D27A3EDF0A52589CBB698519D583B68F72F3961AD77C1358394F29B08FE9F98A29F98311723013591E698557A04A73FB277E3E247083444A6C139ADE01BDE3C368C3A484D6824B33C024C0285CBD665D4F2E4DE87BF79565F08FE09766C16639279A243DAE8395F3E0E5D96E711B210355605A5A8E7B50CEA4BA25E4CB0E273488E223CD69FB699BD937A30D33488EF6076192E1ED08758F7F4774E4C0B8E70955D3CAFE790EB40F7725EB87B8BE6BBECDE1E140966973B5B05FDBFBE05C4BC599888693D96AC0C429B75591EF228A243A6EFDBEEEE49F09383AF2D4AFB6305DE60C5D195A44ED646B0CAFCEC5E445562FFFBB56D444C650E2D892FA99BCE78F2EBF866B154FDB110DDF8CAFB7BE4BEA46724B3952906F0C6E81BE7A17E3C95DF350BB970D2C97499924BDCC4EA0E1DE33AA4E62B5C1FC65FFD2728D81A79AE218AE1C639108323C3D22BA1B8C746CAB0CD535C8661CCA4B6B047790EF148A1B9A88CD3CDD8D79389E2F0D9AAAE135B361ED6778A6F6E03186651692F8DABEDF8872939F694C41E2CAD064FF4C537B92AFD0951DF77302749DCDBC9560FCE001DACAAFAA703BDA73007174C549B69EB031324E31BC9F60049E39254146AEB39BEE8A52CAEA1DD31C42346E44EBCC0771A2548D55ABD085323BA69625845F34831E7518F129CB1D80B76D3C94634F38A1226B5E212D917D593838F51D6CC35F87EB500030AB1446D87F6FFC4717B51C619DDAFD75DBA4C25A09C8C961CDA12A9E01203D678AD2ABB4B7D1BED7EBF0C2932DCE5F0C97F9488DD01A7891DC18D5EEFF6129B7942726A5B5110877260E2A78075C666F4410A2F8A2909D03DE0FBE2BFCA2B068B438ADAF767D804BA85278FB930945D15380281C215BC664B6627EE76CBBC8C5355E607721AAAC069B16B78C2F282795E7BF9B6509E7DC36FD2D45A227BF9D20C5E9678A040B63E964817F98B5F4828EB5D66740C595304D08A0A3C5A50EE3B3F99D2269992DD400A5B452A213DCD2579F7A193FC7FE33E498E91203DE19FF9D54BEBDE9E124A17E784430C38110FE3552861737DE1F2B7678F63417FE2224ED6571D43A8015F6F81362E7B95CB93C86735787F0980B0A3A65549844768EDF0DDEC75A24FA1EF5A26640932F65FF141CAEE2E14506A34E925C21BC268769CD95328675953E79B4B375912434834018ADD9C1832057EE4386C95B6E9407346B4A1582FB3C095E4B0882087DB48F081B5C0DE69ADBC447A6BA2ED6A4F90909911CD3B51ECEC2C6BE6EFE";
    }
}
