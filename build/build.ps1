<#
.SYNOPSIS  Build, test, publish and (optionally) sign TriageKit.
.EXAMPLE   ./build/build.ps1                       # build + test + publish to artifacts/
.EXAMPLE   ./build/build.ps1 -Sign -CertThumbprint ABC123...   # also Authenticode-sign the exe
#>
param([switch]$Sign, [string]$CertThumbprint, [string]$TimestampUrl = 'http://timestamp.digicert.com')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out  = Join-Path $root 'artifacts\TriageKit'
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue

dotnet test  "$root\TriageKit.sln" -c Release
dotnet publish "$root\src\TriageKit.Cli" -c Release -r win-x64 -o $out
Remove-Item "$out\*.pdb" -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force "$out\rules", "$out\tools\Sysinternals" | Out-Null
Copy-Item "$root\src\TriageKit.Core\Resources\indicators.json" "$out\rules\indicators.json"
Copy-Item "$root\docs\USER-GUIDE.md" "$out\README.md"
Copy-Item "$root\docs\tools-README.txt" "$out\tools\README.txt"

if ($Sign) {
    # signtool ships with the Windows SDK. Use a cloud-HSM/EV cert in CI; never commit keys.
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1
    & $signtool.FullName sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 /d "TriageKit" "$out\TriageKit.exe"
    & $signtool.FullName verify /pa /v "$out\TriageKit.exe"
}
Get-FileHash "$out\TriageKit.exe" -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  TriageKit.exe" } | Set-Content "$out\SHA256SUMS.txt"
Compress-Archive -Path "$out\*" -DestinationPath "$root\artifacts\TriageKit-win-x64.zip" -Force
Write-Host "Done: $root\artifacts\TriageKit-win-x64.zip"
