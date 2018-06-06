namespace NaCl.Core
{
    using Base;
    using Internal;

    /// <summary>
    /// A stream cipher based on RFC7539 (i.e., uses 96-bit random nonces).
    /// https://tools.ietf.org/html/rfc7539
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

        /// <summary>
        /// Creates the initial state.
        /// </summary>
        /// <param name="nonce">The nonce.</param>
        /// <param name="counter">The counter.</param>
        /// <returns>Array16&lt;System.UInt32&gt;.</returns>
        protected override Array16<uint> CreateInitialState(byte[] nonce, int counter)
        {
            if (nonce is null || nonce.Length != NonceSizeInBytes()) // The nonce is always 12 bytes.
                throw new CryptographyException($"The nonce length in bytes must be {NonceSizeInBytes()}.");

            // Set the initial state based on https://tools.ietf.org/html/rfc7539#section-2.3
            var state = new Array16<uint>();

            SetSigma(ref state);
            SetKey(ref state, Key);

            // Set Nonce
            state.x12 = (uint)counter;
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
