namespace NaCl.Core
{
    using System;

    using Base;

    /// <summary>
    /// XChaCha20-Poly1305 AEAD construction, as described in <a href="https://tools.ietf.org/html/draft-arciszewski-xchacha-02">draft</a>.
    /// </summary>
    /// <seealso cref="NaCl.Core.Base.SnufflePoly1305" />
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
