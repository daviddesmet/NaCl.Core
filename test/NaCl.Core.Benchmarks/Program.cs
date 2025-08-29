namespace NaCl.Core.Benchmarks;

using System;

using BenchmarkDotNet.Running;

class Program
{
    static void Main(string[] args)
    {
        // Execute following code:
        // $ dotnet run -c release --framework netcoreapp3.1
        // $ dotnet run -c release --framework netcoreapp3.1 --filter "*XChaCha20Poly1305Benchmark*"
        // $ dotnet run -c Release --framework net9.0 --filter "*ChaCha20IntrinsicsBenchmark*"
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
        //BenchmarkRunner.Run<Poly1305Benchmark>();
        //BenchmarkRunner.Run<ChaCha20Benchmark>();
        //BenchmarkRunner.Run<ChaCha20Poly1305Benchmark>();
        //BenchmarkRunner.Run<XChaCha20Benchmark>();
        //BenchmarkRunner.Run<XChaCha20Poly1305Benchmark>();

        Console.ReadLine();
    }
}