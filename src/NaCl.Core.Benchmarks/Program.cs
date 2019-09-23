﻿namespace NaCl.Core.Benchmarks
{
    using System;

    using BenchmarkDotNet.Running;

    class Program
    {
        static void Main(string[] args)
        {
            // Execute following code:
            // $ dotnet run -c release --framework netcoreapp2.0
            //BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
            //BenchmarkRunner.Run<Poly1305Benchmark>();
            BenchmarkRunner.Run<ChaCha20Benchmark>();
            //BenchmarkRunner.Run<ChaCha20Poly1305Benchmark>();
            //BenchmarkRunner.Run<XChaCha20Benchmark>();
            //BenchmarkRunner.Run<XChaCha20Poly1305Benchmark>();

            Console.ReadLine();
        }
    }
}
