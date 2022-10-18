$env:COMPlus_EnableAVX2 = 1
$env:COMPlus_EnableSSE3 = 1
$env:COMPlus_EnableSSE2 = 1
Write-Host "Test Environment: Normal" -ForegroundColor "Cyan"
dotnet test .\test\NaCl.Core.Tests\NaCl.Core.Tests.csproj
if ($LastExitCode -ne 0) {
    Write-Host "Tests failed, aborting build!" -Foreground "Red"
    Exit 1
}

$env:COMPlus_EnableAVX2 = 0
$env:COMPlus_EnableSSE3 = 1
$env:COMPlus_EnableSSE2 = 1
Write-Host "Test Environment: AVX2 Disabled" -ForegroundColor "Cyan"
dotnet test .\test\NaCl.Core.Tests\NaCl.Core.Tests.csproj
if ($LastExitCode -ne 0) {
    Write-Host "Tests failed, aborting build!" -Foreground "Red"
    Exit 1
}

$env:COMPlus_EnableAVX2 = 0
$env:COMPlus_EnableSSE3 = 0
$env:COMPlus_EnableSSE2 = 1
Write-Host "Test Environment: SSE3 Disabled" -ForegroundColor "Cyan"
dotnet test .\test\NaCl.Core.Tests\NaCl.Core.Tests.csproj
if ($LastExitCode -ne 0) {
    Write-Host "Tests failed, aborting build!" -Foreground "Red"
    Exit 1
}

$env:COMPlus_EnableAVX2 = 0
$env:COMPlus_EnableSSE3 = 0
$env:COMPlus_EnableSSE2 = 0
Write-Host "Test Environment: SSE2 Disabled" -ForegroundColor "Cyan"
dotnet test .\test\NaCl.Core.Tests\NaCl.Core.Tests.csproj
if ($LastExitCode -ne 0) {
    Write-Host "Tests failed, aborting build!" -Foreground "Red"
    Exit 1
}

Write-Host "Tests passed!" -ForegroundColor "Green"