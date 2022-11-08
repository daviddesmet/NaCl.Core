namespace NaCl.Core
{
    using System;
    using System.Security.Cryptography;

    using Base;
    using Internal;

    /// <summary>
    /// A stream cipher based upon the <seealso cref="NaCl.Core.Salsa20" /> stream cipher but has a much longer nonce, 192-bit instead of 64-bit.
    /// Stream cipher developed by Daniel J. Bernstein.
    /// </summary>
    /// <seealso cref="NaCl.Core.Base.Salsa20Base" />
    public class XSalsa20 : Salsa20Base
    {
        public const int NONCE_SIZE_IN_BYTES = 24;

        /// <summary>
        /// Initializes a new instance of the <see cref="XSalsa20"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        public XSalsa20(ReadOnlyMemory<byte> key, int initialCounter = 0) : base(key, initialCounter) { }

        /// <inheritdoc />
        protected internal override void SetInitialState(Span<uint> state, ReadOnlySpan<byte> nonce, int counter)
        {
            if (nonce.IsEmpty || nonce.Length != NonceSizeInBytes)
                throw new CryptographicException(FormatNonceLengthExceptionMessage(GetType().Name, nonce.Length, NonceSizeInBytes));

            // Ref: http://cr.yp.to/snuffle/xsalsa-20081128.pdf under 2. Specification - Definition of XSalsa20

            // The first four words in diagonal (0,5,10,15) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
            SetSigma(state);

            // The next eight words (1,2,3,4,11,12,13,14) are taken from the 256-bit key in little-endian order, in 4-byte chunks; and the first 16 bytes of the 24-byte nonce to obtain the subKey.
            Span<byte> subKey = stackalloc byte[KEY_SIZE_IN_BYTES];
            HSalsa20(subKey, nonce);
            SetKey(state, subKey);

            // Words 6-7 is the last 64-bits of the 192-bit nonce, which must not be repeated for the same key.
            state[6] = ArrayUtils.LoadUInt32LittleEndian(nonce, 16); // or ArrayUtils.LoadUInt32LittleEndian(nonce, 0)
            state[7] = ArrayUtils.LoadUInt32LittleEndian(nonce, 20); // or ArrayUtils.LoadUInt32LittleEndian(nonce, 4)

            // Words 8-9 is a 64-bit block counter.
            // TODO: Other implementations uses the nonce, need some tests vectors to validate
            state[8] = (uint)counter; // or ArrayUtils.LoadUInt32LittleEndian(nonce, 8)
            state[9] = 0; // or ArrayUtils.LoadUInt32LittleEndian(nonce, 12)
        }

        /// <summary>
        /// The size of the nonce in bytes.
        /// </summary>
        /// <returns>System.Int32.</returns>
        public override int NonceSizeInBytes => NONCE_SIZE_IN_BYTES;
    }
}