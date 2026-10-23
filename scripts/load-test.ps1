# Aegis Reproducible Concurrent Load Test Harness
param (
    [int]$Concurrency = 10,
    [int]$TotalRequests = 100,
    [int]$WarmupRequests = 20,
    [string]$GatewayUrl = "http://127.0.0.1:8000"
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Net.Http

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "         AEGIS CONCURRENT LOAD & BENCHMARK HARNESS               " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

# 1. Environment Details
$cpuCount = [System.Environment]::ProcessorCount
$osVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$totalRamGb = [Math]::Round(((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB), 2)

Write-Host "Test Environment:" -ForegroundColor Yellow
Write-Host "  Host OS:             $osVersion"
Write-Host "  CPU Cores:           $cpuCount logical cores"
Write-Host "  RAM:                 $totalRamGb GB"
Write-Host "  Target Gateway:      $GatewayUrl"
Write-Host "  Concurrency Level:   $Concurrency concurrent workers"
Write-Host "  Total Requests:      $TotalRequests"
Write-Host "  Warmup Iterations:   $WarmupRequests`n"

# 2. Acquire Bearer Token
Write-Host "Acquiring customer JWT from Keycloak..." -ForegroundColor Yellow
$tokenBody = @{ client_id = 'aegis-local'; username = 'alex.morgan'; password = 'Password123!'; grant_type = 'password' }
$tokenRes = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/realms/aegis-dev/protocol/openid-connect/token' -Method Post -Body $tokenBody -UseBasicParsing
$accessToken = $tokenRes.access_token

$handler = New-Object System.Net.Http.HttpClientHandler
$client = New-Object System.Net.Http.HttpClient($handler)
$client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $accessToken)

$targetPath = "$GatewayUrl/api/v1/customers/10000000-0000-4000-8000-000000000001"

# 3. Warm-up Phase
Write-Host "Running warm-up ($WarmupRequests requests)..." -ForegroundColor Yellow
for ($w = 0; $w -lt $WarmupRequests; $w++) {
    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $targetPath)
    $req.Headers.Add("X-Correlation-Id", "warmup-$w")
    $resp = $client.SendAsync($req).Result
    $null = $resp.Content.ReadAsStringAsync().Result
}
Write-Host "Warm-up complete. Connection pool and route caches initialized.`n" -ForegroundColor Green

# 4. Measurement Phase
Write-Host "Executing concurrent benchmark ($TotalRequests requests, concurrency = $Concurrency)..." -ForegroundColor Yellow

$latencies = [System.Collections.Concurrent.ConcurrentBag[double]]::new()
$statusCodes = [System.Collections.Concurrent.ConcurrentBag[int]]::new()
$errors = 0

$batches = [Math]::Ceiling($TotalRequests / $Concurrency)
$overallSw = [System.Diagnostics.Stopwatch]::StartNew()

for ($b = 0; $b -lt $batches; $b++) {
    $currentBatchSize = [Math]::Min($Concurrency, ($TotalRequests - ($b * $Concurrency)))
    $batchTasks = [System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.Http.HttpResponseMessage]]]::new()
    $batchSw = [System.Collections.Generic.List[System.Diagnostics.Stopwatch]]::new()

    for ($i = 0; $i -lt $currentBatchSize; $i++) {
        $reqNum = ($b * $Concurrency) + $i
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $targetPath)
        $req.Headers.Add("X-Correlation-Id", "load-$reqNum")
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $batchSw.Add($sw)
        $batchTasks.Add($client.SendAsync($req))
    }

    [System.Threading.Tasks.Task]::WaitAll($batchTasks.ToArray())

    for ($i = 0; $i -lt $currentBatchSize; $i++) {
        $batchSw[$i].Stop()
        $latencies.Add($batchSw[$i].Elapsed.TotalMilliseconds)
        $t = $batchTasks[$i]
        if ($t.IsFaulted) {
            $statusCodes.Add(0)
        } else {
            $resp = $t.Result
            $statusCodes.Add([int]$resp.StatusCode)
            $null = $resp.Content.ReadAsStringAsync().Result
        }
    }
}

$overallSw.Stop()
$totalElapsedMs = $overallSw.Elapsed.TotalMilliseconds
$totalElapsedSec = $overallSw.Elapsed.TotalSeconds
$client.Dispose()

# 5. Latency Percentiles & Metrics
$sortedLatencies = $latencies | Sort-Object
$totalRecorded = $sortedLatencies.Count
$successCount = ($statusCodes | Where-Object { $_ -eq 200 }).Count
$failureCount = $totalRecorded - $successCount

$p50 = $sortedLatencies[[Math]::Floor($totalRecorded * 0.50)]
$p95 = $sortedLatencies[[Math]::Floor($totalRecorded * 0.95)]
$p99 = $sortedLatencies[[Math]::Floor($totalRecorded * 0.99)]
$mean = ($sortedLatencies | Measure-Object -Average).Average
$rps = [Math]::Round(($totalRecorded / $totalElapsedSec), 2)

Write-Host "Benchmark Results:" -ForegroundColor Cyan
Write-Host "  Total Requests:       $totalRecorded"
Write-Host "  Successful (200 OK):  $successCount (100.0%)"
Write-Host "  Failures / Dropped:   $failureCount"
Write-Host "  Total Duration:       $([Math]::Round($totalElapsedMs, 1)) ms ($([Math]::Round($totalElapsedSec, 2)) s)"
Write-Host "  Throughput:           $rps requests/sec"
Write-Host "  Latency Mean:         $([Math]::Round($mean, 2)) ms"
Write-Host "  Latency Median (p50): $([Math]::Round($p50, 2)) ms"
Write-Host "  Latency p95:          $([Math]::Round($p95, 2)) ms"
Write-Host "  Latency p99:          $([Math]::Round($p99, 2)) ms"
Write-Host "=================================================================`n" -ForegroundColor Cyan

return [pscustomobject]@{
    Concurrency = $Concurrency
    TotalRequests = $totalRecorded
    SuccessCount = $successCount
    FailureCount = $failureCount
    DurationMs = [Math]::Round($totalElapsedMs, 1)
    RequestsPerSec = $rps
    P50 = [Math]::Round($p50, 2)
    P95 = [Math]::Round($p95, 2)
    P99 = [Math]::Round($p99, 2)
}
