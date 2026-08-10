param(
    [switch]$DotNet,
    [switch]$Node,
    [switch]$Java,
    [switch]$Python,
    [switch]$Go,
    [switch]$Mcp,
    [switch]$All
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repoRoot "sdk-manifest.json"
$manifest = Get-Content $manifestPath | ConvertFrom-Json

if ($All) {
    $DotNet = $true
    $Node = $true
    $Java = $true
    $Python = $true
    $Go = $true
    $Mcp = $true
}

Write-Host "Installing Aegir SDK $($manifest.sdkVersion) Beta-1 components..."

if ($DotNet) {
    Write-Host "DotNet:"
    Write-Host "  dotnet add package $($manifest.packages.dotnet.packageId) --version $($manifest.packages.dotnet.version)"
}

if ($Node) {
    Write-Host "Node:"
    Push-Location (Join-Path $repoRoot "packages/npm")
    npm install
    npm run build
    Pop-Location
}

if ($Java) {
    Write-Host "Java: NOT part of the Beta-1 release - building from source only."
    Push-Location (Join-Path $repoRoot "packages/java")
    mvn -q -DskipTests package
    Pop-Location
}

if ($Python) {
    Write-Host "Python:"
    Push-Location (Join-Path $repoRoot "packages/python")
    python -m pip install -e .
    Pop-Location
}

if ($Go) {
    Write-Host "Go: NOT part of the Beta-1 release - building from source only."
    Push-Location (Join-Path $repoRoot "packages/go")
    go test ./...
    Pop-Location
}

if ($Mcp) {
    Write-Host "MCP:"
    Push-Location (Join-Path $repoRoot "mcp")
    npm install
    Pop-Location
}

Write-Host "Aegir SDK installation wrapper complete."

