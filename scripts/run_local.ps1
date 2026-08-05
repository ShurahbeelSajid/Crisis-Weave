Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $projectRoot ".venv313\Scripts\python.exe"
$streamlitApp = Join-Path $projectRoot "apps\streamlit_app.py"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Missing .venv313. Create it with Python 3.12/3.13 and install '.[dev,ui]'."
}

& $python -c "import sys; raise SystemExit(0 if (3, 12) <= sys.version_info[:2] < (3, 14) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "CrisisWeave requires Python 3.12 or 3.13."
}

& $python -c "import crisisweave, streamlit"
if ($LASTEXITCODE -ne 0) {
    throw "Missing local dependencies. Run: & .\.venv313\Scripts\python.exe -m pip install -e '.[ui]'"
}

$listeners = @{}
foreach ($port in 8000, 8501) {
    $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($listener) {
        $listeners[$port] = $listener
    }
}

if ($listeners.Count -gt 0) {
    $compatibleServicesRunning = $false
    if ($listeners.ContainsKey(8000) -and $listeners.ContainsKey(8501)) {
        try {
            $existingHealth = Invoke-RestMethod `
                -Uri "http://127.0.0.1:8000/health/ready" `
                -TimeoutSec 5
            $existingOpenApi = Invoke-RestMethod `
                -Uri "http://127.0.0.1:8000/openapi.json" `
                -TimeoutSec 5
            $existingFrontend = Invoke-WebRequest `
                -UseBasicParsing `
                -Uri "http://127.0.0.1:8501/_stcore/health" `
                -TimeoutSec 5
            $existingDocuments = Invoke-WebRequest `
                -UseBasicParsing `
                -Uri "http://127.0.0.1:8000/v1/documents?limit=1" `
                -Headers @{ "X-API-Key" = "local-dev-key" } `
                -TimeoutSec 5
            $currentApiListener = Get-NetTCPConnection `
                -State Listen `
                -LocalPort 8000 `
                -ErrorAction Stop |
                    Select-Object -First 1
            $currentFrontendListener = Get-NetTCPConnection `
                -State Listen `
                -LocalPort 8501 `
                -ErrorAction Stop |
                    Select-Object -First 1
            $compatibleServicesRunning = `
                $listeners[8000].LocalAddress -eq "127.0.0.1" -and `
                $listeners[8501].LocalAddress -eq "127.0.0.1" -and `
                $currentApiListener.OwningProcess -eq $listeners[8000].OwningProcess -and `
                $currentFrontendListener.OwningProcess -eq $listeners[8501].OwningProcess -and `
                $existingHealth.status -eq "ok" -and `
                $null -ne $existingOpenApi.paths.'/v1/documents'.delete -and `
                $existingFrontend.StatusCode -eq 200 -and `
                $existingFrontend.Content.Trim() -eq "ok" -and `
                $existingDocuments.StatusCode -eq 200
        }
        catch {
            $compatibleServicesRunning = $false
        }
    }

    if ($compatibleServicesRunning) {
        Write-Host "CrisisWeave is already running and healthy."
        Write-Host "Open the frontend at http://127.0.0.1:8501 and use: local-dev-key"
        Write-Host "No second copy was started."
        return
    }

    $occupiedPorts = @(
        $listeners.GetEnumerator() |
            Sort-Object -Property Key |
            ForEach-Object { "$($_.Key) (process $($_.Value.OwningProcess))" }
    ) -join ", "
    throw "Cannot start CrisisWeave because these required ports are occupied by incompatible or incomplete services: $occupiedPorts. The processes were left untouched."
}

function Set-LocalDefault {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $currentValue = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ([string]::IsNullOrWhiteSpace($currentValue)) {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

Set-LocalDefault "CRISISWEAVE_APP_ENV" "development"
Set-LocalDefault "CRISISWEAVE_API_KEYS" "local-dev-key"
Set-LocalDefault "CRISISWEAVE_API_URL" "http://127.0.0.1:8000"
Set-LocalDefault "CRISISWEAVE_EMBEDDING_PROVIDER" "hash"
Set-LocalDefault "CRISISWEAVE_RERANKER_PROVIDER" "lexical"
Set-LocalDefault "CRISISWEAVE_LLM_PROVIDER" "disabled"
Set-LocalDefault "CRISISWEAVE_WEB_SEARCH_PROVIDER" "disabled"
Set-LocalDefault "CRISISWEAVE_TRANSCRIPTION_PROVIDER" "disabled"
Set-LocalDefault "CRISISWEAVE_RETRIEVAL_CANDIDATE_COUNT" "200"
$localModeDefault = if ($env:CRISISWEAVE_LLM_PROVIDER -eq "disabled") { "true" } else { "false" }
Set-LocalDefault "CRISISWEAVE_UI_LOCAL_MODE" $localModeDefault
$env:STREAMLIT_BROWSER_GATHER_USAGE_STATS = "false"

$logRoot = Join-Path ([IO.Path]::GetTempPath()) "crisisweave-local"
New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
$runId = [Guid]::NewGuid().ToString("N")
$apiStdout = Join-Path $logRoot "api-$runId.stdout.log"
$apiStderr = Join-Path $logRoot "api-$runId.stderr.log"
$apiProcess = $null

try {
    $apiProcess = Start-Process `
        -FilePath $python `
        -ArgumentList @("-m", "crisisweave.cli", "serve", "--host", "127.0.0.1", "--port", "8000") `
        -WorkingDirectory $projectRoot `
        -RedirectStandardOutput $apiStdout `
        -RedirectStandardError $apiStderr `
        -WindowStyle Hidden `
        -PassThru

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $apiProcess.Refresh()
        if ($apiProcess.HasExited) {
            break
        }
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health/ready" -TimeoutSec 2
            if ($health.status -eq "ok") {
                $ready = $true
                break
            }
        }
        catch {
            # Startup connection failures are expected until the API becomes ready.
        }
        Start-Sleep -Seconds 1
    }

    if (-not $ready) {
        $details = @(
            Get-Content -LiteralPath $apiStdout -ErrorAction SilentlyContinue -Tail 40
            Get-Content -LiteralPath $apiStderr -ErrorAction SilentlyContinue -Tail 40
        ) -join [Environment]::NewLine
        throw "The API did not become ready. Logs:`n$details"
    }

    try {
        $openApi = Invoke-RestMethod -Uri "http://127.0.0.1:8000/openapi.json" -TimeoutSec 5
    }
    catch {
        throw "The API became healthy, but its contract could not be verified. Restart the project."
    }
    if ($null -eq $openApi.paths.'/v1/documents'.delete) {
        throw "The running API contract is incompatible with this frontend: evidence reset is unavailable. Restart the project."
    }

    Write-Host "CrisisWeave API is ready at http://127.0.0.1:8000"
    Write-Host "Open the frontend at http://127.0.0.1:8501 and use: local-dev-key"
    Write-Host "Press Ctrl+C to stop both services."

    & $python -m streamlit run $streamlitApp `
        --server.address 127.0.0.1 `
        --server.port 8501 `
        --server.headless true
}
finally {
    if ($apiProcess) {
        $apiProcess.Refresh()
        if (-not $apiProcess.HasExited) {
            & taskkill.exe /PID $apiProcess.Id /T /F 2>$null | Out-Null
        }
    }
}
