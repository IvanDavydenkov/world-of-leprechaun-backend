$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$localRoot = Join-Path $projectRoot '.local'
foreach ($name in @('users-process.json', 'mongo-process.json')) {
    $recordPath = Join-Path $localRoot $name
    if (-not (Test-Path -LiteralPath $recordPath)) { continue }
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    $process = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
    if ($null -eq $process) { continue }
    if ($process.Path -ne $record.path -or $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $record.started) {
        throw "Process identity changed for $recordPath; refusing to stop it."
    }
    Stop-Process -Id $process.Id
    $process.WaitForExit()
}
Write-Host 'Local project processes stopped. Data remains in .local/mongodb.'
