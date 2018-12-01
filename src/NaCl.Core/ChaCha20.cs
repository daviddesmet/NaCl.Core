namespace NaCl.Core
{
    using System;

    using Base;
    using Internal;

    /// <summary>
    /// A stream cipher based on RFC 8439 (previously RFC 7539) (i.e., uses 96-bit random nonces).
    /// https://tools.ietf.org/html/rfc8439#section-2.8
    /// https://tools.ietf.org/html/rfc7539#section-2.8
    ///
    /// This cipher is meant to be used to construct an AEAD with Poly1305.
    /// </summary>
    /// <seealso cref="NaCl.Core.Base.ChaCha20Base" />
    public class ChaCha20 : ChaCha20Base
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ChaCha20"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        public ChaCha20(byte[] key, int initialCounter) : base(key, initialCounter) { }

        /// <inheritdoc />
        protected override Array16<uint> CreateInitialState(ReadOnlySpan<byte> nonce, int counter)
        {
            if (nonce.IsEmpty || nonce.Length != NonceSizeInBytes()) // The nonce is always 12 bytes.
                throw new CryptographyException($"{nameof(ChaCha20)} uses 96-bit nonces, but got a {nonce.Length * 8}-bit nonce. The nonce length in bytes must be {NonceSizeInBytes()}.");

            // Set the initial state based on https://tools.ietf.org/html/rfc8439#section-2.3
            var state = new Array16<uint>();

            // The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
            // The next eight words (4-11) are taken from the 256-bit key in little-endian order, in 4-byte chunks.
            SetSigma(ref state);
            SetKey(ref state, Key);

            // Word 12 is a block counter. Since each block is 64-byte, a 32-bit word is enough for 256 gigabytes of data. Ref: https://tools.ietf.org/html/rfc8439#section-2.3.
            state.x12 = (uint)counter;

            // Words 13-15 are a nonce, which must not be repeated for the same key.
            // The 13th word is the first 32 bits of the input nonce taken as a little-endian integer, while the 15th word is the last 32 bits.
            state.x13 = ByteIntegerConverter.LoadLittleEndian32(nonce, 0);
            state.x14 = ByteIntegerConverter.LoadLittleEndian32(nonce, 4);
            state.x15 = ByteIntegerConverter.LoadLittleEndian32(nonce, 8);

            return state;
        }

        /// <summary>
        /// The size of the randomly generated nonces.
        /// </summary>
        /// <returns>System.Int32.</returns>
        public override int NonceSizeInBytes() => 12;
    }
}
