namespace NaCl.Core.Benchmarks
{
    using System;

    using BenchmarkDotNet.Running;

    class Program
    {
        static void Main(string[] args)
        {
            var c = new ChaCha20Benchmark();
            c.Size = 10_000;
            c.Setup();
            c.Encrypt();
            
            // Execute following code:
            // $ dotnet run -c release --framework netcoreapp3.1
            // $ dotnet run -c release --framework netcoreapp3.1 --filter *XChaCha20Poly1305Benchmark*
            //BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
            //BenchmarkRunner.Run<Poly1305Benchmark>();
            BenchmarkRunner.Run<ChaCha20Benchmark>();
            //BenchmarkRunner.Run<Salsa20Benchmark>();
            //BenchmarkRunner.Run<ChaCha20Poly1305Benchmark>();
            //BenchmarkRunner.Run<XChaCha20Benchmark>();
            //BenchmarkRunner.Run<XSalsa20Benchmark>();
            //BenchmarkRunner.Run<XChaCha20Poly1305Benchmark>();

            Console.ReadLine();
        }
    }
}
