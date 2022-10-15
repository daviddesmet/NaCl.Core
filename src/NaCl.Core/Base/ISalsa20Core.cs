using System;

namespace NaCl.Core.Base;
internal interface ISalsa20Core
{
    void HSalsa20(Span<byte> subKey, ReadOnlySpan<byte> nonce);
    void Process(ReadOnlySpan<byte> nonce, Span<byte> output, ReadOnlySpan<byte> input, int offset = 0);
    void ProcessKeyStreamBlock(ReadOnlySpan<byte> nonce, int counter, Span<byte> block);
}