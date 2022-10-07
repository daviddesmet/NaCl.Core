namespace NaCl.Core
{
    using System;
    using System.Security.Cryptography;

    using Base;
    using Internal;

    /// <summary>
    /// A stream cipher part of the family of 256-bit stream ciphers designed in 2005 and submitted to eSTREAM, the ECRYPT Stream Cipher Project.
    /// Stream cipher developed by Daniel J. Bernstein.
    /// </summary>
    /// <seealso cref="NaCl.Core.Base.Salsa20Base" />
    public class Salsa20 : Salsa20Base
    {
        public const int NONCE_SIZE_IN_BYTES = 8;

        /// <summary>
        /// Initializes a new instance of the <see cref="Salsa20"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        public Salsa20(ReadOnlyMemory<byte> key, int initialCounter = 0) : base(key, initialCounter) { }

        /// <inheritdoc />
        protected override void SetInitialState(Span<uint> state, ReadOnlySpan<byte> nonce, int counter)
        {
            if (nonce.IsEmpty || nonce.Length != NonceSizeInBytes)
                throw new CryptographicException(FormatNonceLengthExceptionMessage(GetType().Name, nonce.Length, NonceSizeInBytes));

            // Ref: http://cr.yp.to/snuffle/xsalsa-20081128.pdf under 2. Specification - Review of Salsa20

            // The first four words in diagonal (0,5,10,15) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
            // The next eight words (1,2,3,4,11,12,13,14) are taken from the 256-bit key in little-endian order, in 4-byte chunks.
            SetSigma(state);
            SetKey(state, Key.Span);

            // Words 6-7 is a 64-bit nonce, which must not be repeated for the same key.
            state[6] = ArrayUtils.LoadUInt32LittleEndian(nonce, 0);
            state[7] = ArrayUtils.LoadUInt32LittleEndian(nonce, 4);

            // Words 8-9 is a 64-bit block counter, the position of the 512-bit output block.
            state[8] = (uint)counter;
            state[9] = 0;
        }

        /// <summary>
        /// The size of the nonce in bytes.
        /// </summary>
        /// <returns>System.Int32.</returns>
        public override int NonceSizeInBytes => NONCE_SIZE_IN_BYTES;
    }
}