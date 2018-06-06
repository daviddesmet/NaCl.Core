namespace NaCl.Core
{
    using System;

    using Base;

    /// <summary>
    /// XChaCha20-Poly1305 AEAD construction, compatible with <a href="https://tools.ietf.org/html/rfc7539#section-2.8">RFC 7539, section 2.8</a>.
    /// </summary>
    /// <seealso cref="NaCl.Core.Base.SnufflePoly1305" />
    [Obsolete("Alpha release, requires more testing...")]
    public class XChaCha20Poly1305 : SnufflePoly1305
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="XChaCha20Poly1305"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        public XChaCha20Poly1305(byte[] key) : base(key) { }

        /// <summary>
        /// Creates the snuffle instance.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="initialCounter">The initial counter.</param>
        /// <returns>Snuffle.</returns>
        protected override Snuffle CreateSnuffleInstance(byte[] key, int initialCounter) => new XChaCha20(key, initialCounter);
    }
}
