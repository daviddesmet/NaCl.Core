namespace NaCl.Core.Benchmarks
{
    using System;

    using BenchmarkDotNet.Running;

    class Program
    {
        static void Main(string[] args)
        {
            // Execute following code:
            // $ dotnet run -c release --framework netcoreapp3.1

            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
            //BenchmarkRunner.Run<Poly1305Benchmark>(args);
            //BenchmarkRunner.Run<ChaCha20Benchmark>(args);
            //BenchmarkRunner.Run<ChaCha20Poly1305Benchmark>(args);
            //BenchmarkRunner.Run<XChaCha20Benchmark>(args);
            //BenchmarkRunner.Run<XChaCha20Poly1305Benchmark>(args);

            Console.ReadLine();
        }
    }
}
