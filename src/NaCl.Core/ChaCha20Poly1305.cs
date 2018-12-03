namespace NaCl.Core
{
    using Base;

    /// <summary>
    /// ChaCha20-Poly1305 AEAD construction, as described in <a href="https://tools.ietf.org/html/rfc8439#section-2.8">RFC 8439, section 2.8</a>.
    /// </summary>
    /// <seealso cref="NaCl.Core.Base.SnufflePoly1305" />
    public class ChaCha20Poly1305 : SnufflePoly1305
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ChaCha20Poly1305"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        public ChaCha20Poly1305(in byte[] key) : base(key) { }

        /// <summary>
        /// Creates the snuffle instance.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        /// <returns>Snuffle.</returns>
        protected override Snuffle CreateSnuffleInstance(in byte[] key, int initialCounter) => new ChaCha20(key, initialCounter);
    }
}
