using System;
using System.Collections.Generic;
using System.Text;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.CsProj;

namespace NaCl.Core.Benchmarks
{
    public class MultipleRuntimes : ManualConfig
    {
        public MultipleRuntimes()
        {
            //Add(Job.Default.With(CsProjClassicNetToolchain.Net47));
            //Add(Job.Default.With(CsProjCoreToolchain.NetCoreApp21));
            Add(Job.Default.With(CsProjCoreToolchain.NetCoreApp30));
        }
    }
}
