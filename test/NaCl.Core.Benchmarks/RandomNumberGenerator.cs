using System;

namespace NaCl.Core.Benchmarks
{
#if NET48
    public static class RandomNumberGenerator
    {
        public static void Fill(Span<byte> data)
        {
            var random = System.Security.Cryptography.RandomNumberGenerator.Create();
            var dataBytes = new byte[data.Length];
            random.GetBytes(dataBytes);
            dataBytes.CopyTo(data);
        }
    }
#endif
}
