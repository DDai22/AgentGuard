$Language = if ($args.Count -gt 0) { $args[0] } else { "zh" }
if ($Language -notin @("zh", "en")) { throw "Language must be zh or en." }

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonw = Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\pythonw.exe"
if (-not (Test-Path -LiteralPath $pythonw)) {
    $python = (Get-Command python -ErrorAction Stop).Source
    $pythonw = Join-Path (Split-Path -Parent $python) "pythonw.exe"
}

Get-CimInstance Win32_Process |
    Where-Object {
        $_.Name -eq "pythonw.exe" -and
        $_.CommandLine -match "(?:^|\s)-m\s+agentguard\s+ui(?:\s|$)"
    } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

& "$env:SystemRoot\System32\logman.exe" stop "NT Kernel Logger" -ets 2>$null | Out-Null

Start-Process `
    -FilePath $pythonw `
    -ArgumentList @("-m", "agentguard", "ui", "--language", $Language) `
    -WorkingDirectory $projectRoot `
    -WindowStyle Hidden
