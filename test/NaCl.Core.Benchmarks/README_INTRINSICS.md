# Hardware Intrinsics Benchmarks

This directory contains benchmarks for testing hardware intrinsics performance in NaCl.Core.

## Running Intrinsics Benchmarks

To properly benchmark different SIMD instruction sets, you need to run separate processes with environment variables set at startup:

### Testing Scalar Performance (Disable SIMD)
```bash
COMPlus_EnableAVX2=0 COMPlus_EnableSSE2=0 COMPlus_EnableAdvSimd=0 dotnet run -c Release -- --filter "*Salsa20*"
```

### Testing SSE2 Performance (x86/x64 only)
```bash
COMPlus_EnableAVX2=0 COMPlus_EnableSSE2=1 dotnet run -c Release -- --filter "*Salsa20*"
```

### Testing AVX2 Performance (x86/x64 only)
```bash
COMPlus_EnableAVX2=1 COMPlus_EnableSSE2=1 dotnet run -c Release -- --filter "*Salsa20*"
```

### Testing ARM AdvSIMD Performance (ARM64 only)
```bash
COMPlus_EnableAdvSimd=1 dotnet run -c Release -- --filter "*Salsa20*"
```

### Testing Default Performance (Runtime Detection)
```bash
dotnet run -c Release -- --filter "*Salsa20*"
```

## Available Benchmarks

- `ChaCha20IntrinsicsBenchmark` - Tests ChaCha20 cipher performance with different data sizes
- `ChaCha20CoreBenchmark` - Focused ChaCha20 core operation benchmarks (1MB fixed size)
- `Salsa20IntrinsicsBenchmark` - Tests Salsa20 cipher performance 
- `Poly1305IntrinsicsBenchmark` - Tests Poly1305 MAC computation performance  
- `ArrayUtilsIntrinsicsBenchmark` - Tests vectorized array operations performance

## Notes

1. Environment variables must be set **before** the .NET runtime starts for them to take effect
2. Some instruction sets may not be available on your hardware (e.g., AVX2 on older CPUs)
3. On ARM systems, use AdvSIMD; on x86/x64, use SSE2/AVX2
4. The runtime automatically selects the best available instruction set when no environment variables are set

## Example Benchmark Runs

### Quick Performance Test
```bash
# Run all intrinsics benchmarks with default settings
dotnet run -c Release -- --filter "*Intrinsics*" --job=short
```

### Detailed SIMD Comparison
```bash
# 1. Test with scalar performance (no SIMD)
COMPlus_EnableAVX2=0 COMPlus_EnableSSE2=0 COMPlus_EnableAdvSimd=0 \
dotnet run -c Release -- --filter "*ChaCha20Core*" --job=short --exporters json

# 2. Test with SSE2 only (x86/x64)
COMPlus_EnableAVX2=0 COMPlus_EnableSSE2=1 \
dotnet run -c Release -- --filter "*ChaCha20Core*" --job=short --exporters json

# 3. Test with AVX2 enabled (x86/x64)
COMPlus_EnableAVX2=1 COMPlus_EnableSSE2=1 \
dotnet run -c Release -- --filter "*ChaCha20Core*" --job=short --exporters json

# 4. Test default (auto-detection)
dotnet run -c Release -- --filter "*ChaCha20Core*" --job=short --exporters json
```

### Testing Specific Algorithms
```bash
# Test ChaCha20 performance
dotnet run -c Release -- --filter "*ChaCha20*"

# Test Salsa20 performance  
dotnet run -c Release -- --filter "*Salsa20*"

# Test Poly1305 MAC performance
dotnet run -c Release -- --filter "*Poly1305*"

# Test array utilities performance
dotnet run -c Release -- --filter "*ArrayUtils*"
```

### Performance Comparison Script
```bash
#!/bin/bash
# compare_simd.sh - Compare SIMD performance

echo "=== Scalar Performance ==="
COMPlus_EnableAVX2=0 COMPlus_EnableSSE2=0 COMPlus_EnableAdvSimd=0 \
dotnet run -c Release -- --filter "*ChaCha20Core*" --job=short

echo "=== Intrinsics Performance ==="
dotnet run -c Release -- --filter "*ChaCha20Core*" --job=short
```

This approach provides reliable measurements by ensuring environment variables are set before the .NET runtime initializes.