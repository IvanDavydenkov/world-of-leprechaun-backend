param([switch]$PrepareOnly, [switch]$WithVPN)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$localRoot = Join-Path $projectRoot '.local'
$envPath = Join-Path $projectRoot '.env'
[void](New-Item -ItemType Directory -Force -Path $localRoot)

if (-not (Test-Path -LiteralPath $envPath)) {
    Copy-Item -LiteralPath (Join-Path $projectRoot '.env.example') -Destination $envPath
}

function New-RandomValue([bool]$Base64) {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    if ($Base64) { return [Convert]::ToBase64String($bytes) }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

$content = [IO.File]::ReadAllText($envPath)
foreach ($key in @('MONGO_ROOT_PASSWORD', 'USERS_MONGO_PASSWORD', 'VPN_CONFIGS_MONGO_PASSWORD', 'VPN_CONFIG_ENCRYPTION_KEY', 'INTERNAL_SERVICE_TOKEN')) {
    $pattern = '(?m)^' + $key + '=[ \t]*\r?$'
    if ([regex]::IsMatch($content, $pattern)) {
        $value = New-RandomValue ($key -eq 'VPN_CONFIG_ENCRYPTION_KEY')
        $content = [regex]::Replace($content, $pattern, ($key + '=' + $value))
    }
    elseif (-not [regex]::IsMatch($content, ('(?m)^' + $key + '='))) {
        $value = New-RandomValue ($key -eq 'VPN_CONFIG_ENCRYPTION_KEY')
        $content += "`n" + $key + '=' + $value + "`n"
    }
}
[IO.File]::WriteAllText($envPath, $content, (New-Object Text.UTF8Encoding $false))
if ($PrepareOnly) { Write-Host 'Prepared .env; add YANDEX_CLIENT_ID and YANDEX_CLIENT_SECRET there.'; return }

function Test-Port([int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try { return $client.ConnectAsync('127.0.0.1', $Port).Wait(300) -and $client.Connected }
    catch { return $false }
    finally { $client.Dispose() }
}

function Read-OwnedProcess([string]$RecordPath) {
    if (-not (Test-Path -LiteralPath $RecordPath)) { return $null }
    $record = Get-Content -LiteralPath $RecordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $process = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
    if ($null -eq $process) { return $null }
    if ($process.Path -ne $record.path -or $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $record.started) {
        throw "Process identity changed for $RecordPath; refusing to control it."
    }
    return $process
}

function Save-OwnedProcess($Process, [string]$RecordPath) {
    $launchedProcessId = $Process.Id
    for ($identityAttempt = 0; $identityAttempt -lt 50; $identityAttempt++) {
        $Process = Get-Process -Id $launchedProcessId -ErrorAction Stop
        if ($Process.Path) { break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $Process.Path) { throw "Cannot verify executable path for process $launchedProcessId." }
    @{ pid = $Process.Id; path = $Process.Path; started = $Process.StartTime.ToUniversalTime().Ticks.ToString() } |
        ConvertTo-Json | Set-Content -LiteralPath $RecordPath -Encoding UTF8
}

$mongod = Get-Command mongod -ErrorAction SilentlyContinue
$mongoExecutable = $null
if ($mongod) { $mongoExecutable = $mongod.Source }
else {
    $mongoInstallation = Join-Path $env:ProgramFiles 'MongoDB\Server'
    if (Test-Path -LiteralPath $mongoInstallation) {
        $mongoExecutable = Get-ChildItem -LiteralPath $mongoInstallation -Filter mongod.exe -Recurse |
            Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
}
if (-not $mongoExecutable) { throw 'MongoDB Server is not installed. Use Docker Compose or install MongoDB Server.' }
$goExecutable = (Get-Command go -ErrorAction Stop).Source
$mongoRecord = Join-Path $localRoot 'mongo-process.json'
$apiRecord = Join-Path $localRoot 'users-process.json'
$mongoProcess = Read-OwnedProcess $mongoRecord
if (-not $mongoProcess) {
    if (Test-Port 27018) { throw 'Port 27018 is already occupied by another process.' }
    $dataPath = Join-Path $localRoot 'mongodb'
    [void](New-Item -ItemType Directory -Force -Path $dataPath)
    $mongoProcess = Start-Process -FilePath $mongoExecutable -ArgumentList @(
        '--bind_ip', '127.0.0.1', '--port', '27018', '--dbpath', ('"' + $dataPath + '"'),
        '--logpath', ('"' + (Join-Path $localRoot 'mongodb.log') + '"'), '--logappend'
    ) -WindowStyle Hidden -PassThru
    Save-OwnedProcess $mongoProcess $mongoRecord
}
for ($attempt = 0; $attempt -lt 50 -and -not (Test-Port 27018); $attempt++) { Start-Sleep -Milliseconds 100 }
if (-not (Test-Port 27018)) { throw 'Local MongoDB did not start; inspect .local/mongodb.log.' }

$existingAPI = Read-OwnedProcess $apiRecord
if ($existingAPI) { Stop-Process -Id $existingAPI.Id; $existingAPI.WaitForExit() }
if (Test-Port 8080) { throw 'Port 8080 is already occupied by another process.' }
$apiExecutable = Join-Path $localRoot 'users-api.exe'
Push-Location $projectRoot
try {
    & $goExecutable build -o $apiExecutable ./services/users/cmd/api
    if ($LASTEXITCODE -ne 0) { throw 'Backend build failed.' }
} finally { Pop-Location }

# Read only application keys. Do not execute .env as PowerShell code.
$settings = @{}
foreach ($line in ($content -split "`r?`n")) {
    if ($line -match '^(YANDEX_CLIENT_ID|YANDEX_CLIENT_SECRET|YANDEX_REDIRECT_URL|ADMIN_YANDEX_ID|FRONTEND_ORIGIN|AUTH_SUCCESS_REDIRECT_URL|AUTH_LOGOUT_REDIRECT_URL|INTERNAL_SERVICE_TOKEN|VPN_API_URL)=(.*)$') {
        $settings[$Matches[1]] = $Matches[2].Trim().Trim('"').Trim("'")
    }
}
$settings['USERS_HTTP_ADDR'] = '127.0.0.1:8080'
$settings['MONGO_URI'] = 'mongodb://127.0.0.1:27018'
$settings['MONGO_DATABASE'] = 'users_local'
$previous = @{}
try {
    foreach ($key in $settings.Keys) {
        $previous[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, $settings[$key], 'Process')
    }
    $apiProcess = Start-Process -FilePath $apiExecutable -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $localRoot 'users.stdout.log') -RedirectStandardError (Join-Path $localRoot 'users.stderr.log')
    Save-OwnedProcess $apiProcess $apiRecord
} finally {
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key, $previous[$key], 'Process') }
}
for ($attempt = 0; $attempt -lt 30 -and -not (Test-Port 8080); $attempt++) { Start-Sleep -Milliseconds 100 }
if (-not (Test-Port 8080)) { throw 'Backend did not start; inspect .local/users.stderr.log.' }
Write-Host 'Backend: http://localhost:8080/'
Write-Host 'Local-only MongoDB: 127.0.0.1:27018, database users_local (no authentication).'
if (-not $settings['YANDEX_CLIENT_ID'] -or -not $settings['YANDEX_CLIENT_SECRET']) {
    Write-Host 'OAuth disabled: fill YANDEX_CLIENT_ID and YANDEX_CLIENT_SECRET in .env, then rerun this script.'
}

if ($WithVPN) {
    $vpnRecord = Join-Path $localRoot 'vpn-process.json'
    $existingVPN = Read-OwnedProcess $vpnRecord
    if ($existingVPN) { Stop-Process -Id $existingVPN.Id; $existingVPN.WaitForExit() }
    if (Test-Port 8081) { throw 'Port 8081 is occupied by another process.' }
    $vpnExecutable = Join-Path $localRoot 'vpn-api.exe'
    Push-Location $projectRoot
    try {
        & $goExecutable build -o $vpnExecutable ./services/vpn-configs/cmd/api
        if ($LASTEXITCODE -ne 0) { throw 'VPN service build failed.' }
    } finally { Pop-Location }
    $vpnSettings = @{}
    foreach ($line in ($content -split "`r?`n")) {
        if ($line -match '^(VPN_HOST_ADDRESS|VPN_HOST_USERNAME|VPN_HOST_PASSWORD|VPN_CONFIG_ENCRYPTION_KEY|VPN_KNOWN_HOSTS_FILE|VPN_PUBLIC_ENDPOINT|INTERNAL_SERVICE_TOKEN)=(.*)$') {
            $vpnSettings[$Matches[1]] = $Matches[2].Trim().Trim('"').Trim("'")
        }
    }
    $vpnSettings['VPN_CONFIGS_HTTP_ADDR'] = '127.0.0.1:8081'
    $vpnSettings['MONGO_URI'] = 'mongodb://127.0.0.1:27018'
    $vpnSettings['MONGO_DATABASE'] = 'vpn_configs_local'
    $vpnSettings['USERS_API_URL'] = 'http://127.0.0.1:8080'
    $previousVPN = @{}
    try {
        foreach ($key in $vpnSettings.Keys) {
            $previousVPN[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
            [Environment]::SetEnvironmentVariable($key, $vpnSettings[$key], 'Process')
        }
        $vpnProcess = Start-Process -FilePath $vpnExecutable -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput (Join-Path $localRoot 'vpn.stdout.log') -RedirectStandardError (Join-Path $localRoot 'vpn.stderr.log')
        Save-OwnedProcess $vpnProcess $vpnRecord
    } finally {
        foreach ($key in $previousVPN.Keys) { [Environment]::SetEnvironmentVariable($key, $previousVPN[$key], 'Process') }
    }
    for ($attempt = 0; $attempt -lt 30 -and -not (Test-Port 8081); $attempt++) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Port 8081)) { throw 'VPN service did not start; inspect .local/vpn.stderr.log.' }
    Write-Host 'VPN API: http://127.0.0.1:8081/ (internal; public admin routes are on users :8080).'
}
