namespace NaCl.Core;

using System;
using System.Security.Cryptography;

using Base;
using Internal;

/// <summary>
/// A stream cipher based on <a href="https://tools.ietf.org/html/rfc8439#section-2.8">RFC 8439</a> (previously <a href="https://tools.ietf.org/html/rfc7539#section-2.8">RFC 7539</a>) (i.e., uses 96-bit random nonces).
///
/// This cipher is meant to be used to construct an AEAD with Poly1305.
/// </summary>
/// <seealso cref="NaCl.Core.Base.ChaCha20Base" />
/// <seealso href="https://tools.ietf.org/html/rfc8439#section-2.8">RFC 8439</seealso>
/// <seealso href="https://tools.ietf.org/html/rfc7539#section-2.8">RFC 7539</seealso>
public class ChaCha20 : ChaCha20Base
{
    public const int NONCE_SIZE_IN_BYTES = 12;

    /// <summary>
    /// Initializes a new instance of the <see cref="ChaCha20"/> class.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="initialCounter">The initial counter.</param>
    public ChaCha20(ReadOnlyMemory<byte> key, int initialCounter) : base(key, initialCounter) { }

    /// <inheritdoc />
    protected override void SetInitialState(Span<uint> state, ReadOnlySpan<byte> nonce, int counter)
    {
        if (nonce.IsEmpty || nonce.Length != NonceSizeInBytes)
            throw new CryptographicException(FormatNonceLengthExceptionMessage(GetType().Name, nonce.Length, NonceSizeInBytes));

        // The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
        // The next eight words (4-11) are taken from the 256-bit key in little-endian order, in 4-byte chunks.
        SetSigma(state);
        SetKey(state, Key.Span);

        // Word 12 is a block counter. Since each block is 64-byte, a 32-bit word is enough for 256 gigabytes of data. Ref: https://tools.ietf.org/html/rfc8439#section-2.3.
        state[12] = (uint)counter;

        // Words 13-15 are a nonce, which must not be repeated for the same key.
        // The 13th word is the first 32 bits of the input nonce taken as a little-endian integer, while the 15th word is the last 32 bits.
        state[13] = ArrayUtils.LoadUInt32LittleEndian(nonce, 0);
        state[14] = ArrayUtils.LoadUInt32LittleEndian(nonce, 4);
        state[15] = ArrayUtils.LoadUInt32LittleEndian(nonce, 8);
    }

    /// <summary>
    /// The size of the nonce in bytes.
    /// </summary>
    /// <returns>System.Int32.</returns>
    public override int NonceSizeInBytes => NONCE_SIZE_IN_BYTES;
}