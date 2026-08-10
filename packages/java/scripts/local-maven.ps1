param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Goals
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$targetRoot = Join-Path $projectRoot "target"
$classesRoot = Join-Path $targetRoot "classes"
$testClassesRoot = Join-Path $targetRoot "test-classes"
$artifactName = "aegir-security-0.1.1-beta.1.jar"
$artifactPath = Join-Path $targetRoot $artifactName
$sourcesArtifactPath = Join-Path $targetRoot "aegir-security-0.1.1-beta.1-sources.jar"
$javadocRoot = Join-Path $targetRoot "apidocs"
$javadocArtifactPath = Join-Path $targetRoot "aegir-security-0.1.1-beta.1-javadoc.jar"

function Compile-Sources {
    param(
        [string]$SourceRoot,
        [string]$OutputRoot,
        [string[]]$AdditionalClassPath = @()
    )

    New-Item -ItemType Directory -Force $OutputRoot | Out-Null
    $sources = Get-ChildItem -Recurse $SourceRoot -Filter *.java | ForEach-Object FullName
    if ($sources.Count -eq 0) {
        return
    }

    $args = @("-d", $OutputRoot)
    if ($AdditionalClassPath.Count -gt 0) {
        $args += @("-cp", ($AdditionalClassPath -join [IO.Path]::PathSeparator))
    }
    $args += $sources

    & javac @args
    if ($LASTEXITCODE -ne 0) {
        throw "javac failed."
    }
}

if ($Goals.Count -eq 0) {
    $Goals = @("test")
}

if ($Goals -contains "clean") {
    Remove-Item -Recurse -Force $targetRoot -ErrorAction SilentlyContinue
}

if ($Goals -contains "compile" -or $Goals -contains "test" -or $Goals -contains "package") {
    Compile-Sources -SourceRoot (Join-Path $projectRoot "src\main\java") -OutputRoot $classesRoot
}

if ($Goals -contains "test") {
    Compile-Sources -SourceRoot (Join-Path $projectRoot "src\test\java") -OutputRoot $testClassesRoot -AdditionalClassPath @($classesRoot)
    & java -cp ($classesRoot + [IO.Path]::PathSeparator + $testClassesRoot) cloud.foxlin.aegir.security.AegirSecurityClientTest
    if ($LASTEXITCODE -ne 0) {
        throw "Java test run failed."
    }
}

if ($Goals -contains "package") {
    New-Item -ItemType Directory -Force $targetRoot | Out-Null
    & jar --create --file $artifactPath -C $classesRoot .
    if ($LASTEXITCODE -ne 0) {
        throw "jar packaging failed."
    }

    & jar --create --file $sourcesArtifactPath -C (Join-Path $projectRoot "src\main\java") .
    if ($LASTEXITCODE -ne 0) {
        throw "sources jar packaging failed."
    }

    $mainSources = Get-ChildItem -Recurse (Join-Path $projectRoot "src\main\java") -Filter *.java | ForEach-Object FullName
    if ($mainSources.Count -gt 0) {
        Remove-Item -Recurse -Force $javadocRoot -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force $javadocRoot | Out-Null
        & javadoc -quiet -d $javadocRoot @mainSources
        if ($LASTEXITCODE -ne 0) {
            throw "javadoc generation failed."
        }

        & jar --create --file $javadocArtifactPath -C $javadocRoot .
        if ($LASTEXITCODE -ne 0) {
            throw "javadoc jar packaging failed."
        }
    }

    Write-Host "Created $artifactPath"
    Write-Host "Created $sourcesArtifactPath"
    Write-Host "Created $javadocArtifactPath"
}
