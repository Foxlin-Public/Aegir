# Copyright Foxlin Industries. Installed JDK only; no package downloads.
param()
$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $PSScriptRoot
$classesDirectory = Join-Path $projectDirectory 'target/classes'
$testsDirectory = Join-Path $projectDirectory 'target/test-classes'
New-Item -ItemType Directory -Force $classesDirectory,$testsDirectory | Out-Null
$mainSources = @(Get-ChildItem -LiteralPath (Join-Path $projectDirectory 'src/main/java') -Recurse -Filter '*.java' | ForEach-Object FullName)
$testSources = @(Get-ChildItem -LiteralPath (Join-Path $projectDirectory 'src/test/java') -Recurse -Filter '*.java' | ForEach-Object FullName)
& javac --release 11 -d $classesDirectory @mainSources
if ($LASTEXITCODE -ne 0) { throw 'Java compilation failed.' }
& javac --release 11 -cp $classesDirectory -d $testsDirectory @testSources
if ($LASTEXITCODE -ne 0) { throw 'Java test compilation failed.' }
$temporaryKeystore = Join-Path $projectDirectory ('target/authorization-test-' + [guid]::NewGuid().ToString('N') + '.p12')
$previousTestPassword = $env:AEGIR_JAVA_TEST_KEYSTORE_PASS
try {
    $env:AEGIR_JAVA_TEST_KEYSTORE_PASS = [guid]::NewGuid().ToString('N')
    & keytool -genkeypair -alias aegir-test -keyalg RSA -keysize 2048 -validity 2 -dname 'CN=localhost, O=Foxlin Industries' -ext 'SAN=ip:127.0.0.1,dns:localhost' -storetype PKCS12 -keystore $temporaryKeystore -storepass:env AEGIR_JAVA_TEST_KEYSTORE_PASS -keypass:env AEGIR_JAVA_TEST_KEYSTORE_PASS -noprompt
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic TLS fixture generation failed.' }
    $testClassPath = $classesDirectory + [IO.Path]::PathSeparator + $testsDirectory
    & java -cp $testClassPath cloud.foxlin.aegir.security.AegirSecurityClientTest $temporaryKeystore
    if ($LASTEXITCODE -ne 0) { throw 'Retained Java suite failed.' }
    & java -cp $testClassPath cloud.foxlin.aegir.security.LegacySecurityHardeningTest $temporaryKeystore
    if ($LASTEXITCODE -ne 0) { throw 'Legacy hardening Java suite failed.' }
    & java -cp $testClassPath cloud.foxlin.aegir.security.AuthorizationIntegrationTest $temporaryKeystore
    if ($LASTEXITCODE -ne 0) { throw 'Authorization Java suite failed.' }
    & java -cp $testClassPath cloud.foxlin.aegir.security.DiagnosticsLifetimeTest $temporaryKeystore
    if ($LASTEXITCODE -ne 0) { throw 'Diagnostic lifetime Java suite failed.' }
} finally {
    $env:AEGIR_JAVA_TEST_KEYSTORE_PASS = $previousTestPassword
    if (Test-Path -LiteralPath $temporaryKeystore) { Remove-Item -LiteralPath $temporaryKeystore }
}
