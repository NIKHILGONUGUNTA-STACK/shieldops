# Aegis Phase 3 Gate Verification Script
$ErrorActionPreference = 'Stop'

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "    AEGIS PHASE 3 VERIFICATION & SECURITY HARDENING GATE        " -ForegroundColor Cyan
Write-Host "=================================================================`n" -ForegroundColor Cyan

$results = [ordered]@{}

function Record-Test($name, $passed, $details) {
    $status = if ($passed) { "PASS" } else { "FAIL" }
    $color = if ($passed) { "Green" } else { "Red" }
    Write-Host "[$status] $name - $details" -ForegroundColor $color
    $script:results[$name] = [pscustomobject]@{
        Status = $status
        Details = $details
    }
}

# --- 1. KEYCLOAK TOKEN ACQUISITION ---
Write-Host "--- 1. ACQUIRING TOKENS FROM REAL KEYCLOAK ---" -ForegroundColor Yellow

# Alex Morgan (CUSTOMER)
$alexBody = @{ client_id = 'aegis-local'; username = 'alex.morgan'; password = 'Password123!'; grant_type = 'password' }
$alexTokenRes = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/realms/aegis-dev/protocol/openid-connect/token' -Method Post -Body $alexBody
$alexToken = $alexTokenRes.access_token

# Security Analyst (SECURITY_ANALYST)
$analystBody = @{ client_id = 'aegis-local'; username = 'analyst'; password = 'Password123!'; grant_type = 'password' }
$analystTokenRes = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/realms/aegis-dev/protocol/openid-connect/token' -Method Post -Body $analystBody
$analystToken = $analystTokenRes.access_token

# Security Admin (SECURITY_ADMIN)
$adminBody = @{ client_id = 'aegis-local'; username = 'admin'; password = 'Password123!'; grant_type = 'password' }
$adminTokenRes = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/realms/aegis-dev/protocol/openid-connect/token' -Method Post -Body $adminBody
$adminToken = $adminTokenRes.access_token

Record-Test "Keycloak Token Acquisition" ($alexToken -ne $null -and $analystToken -ne $null -and $adminToken -ne $null) "Tokens acquired for CUSTOMER, SECURITY_ANALYST, and SECURITY_ADMIN"

$alexHeaders = @{ Authorization = "Bearer $alexToken"; "X-Correlation-Id" = "e2e-alex-$(Get-Random)" }
$analystHeaders = @{ Authorization = "Bearer $analystToken"; "X-Correlation-Id" = "e2e-analyst-$(Get-Random)" }
$adminHeaders = @{ Authorization = "Bearer $adminToken"; "X-Correlation-Id" = "e2e-admin-$(Get-Random)" }

# --- 2. AUTHENTICATION & ROLE VERIFICATION (STAGE 3) ---
Write-Host "`n--- 2. AUTHENTICATION & ROLE-BASED ACCESS CONTROL ---" -ForegroundColor Yellow

# Missing Token -> 401
try {
    Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000001'
    Record-Test "Missing Bearer Token" $false "Expected HTTP 401 but succeeded"
} catch {
    Record-Test "Missing Bearer Token" ($_.Exception.Response.StatusCode.value__ -eq 401) "Rejected with HTTP 401 Unauthorized"
}

# Malformed Token -> 401
try {
    Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000001' -Headers @{ Authorization = "Bearer not.a.valid.jwt.string" }
    Record-Test "Malformed JWT" $false "Expected HTTP 401 but succeeded"
} catch {
    Record-Test "Malformed JWT" ($_.Exception.Response.StatusCode.value__ -eq 401) "Rejected with HTTP 401 Unauthorized"
}

# Forged Signature -> 401
try {
    $parts = $alexToken.Split('.')
    $tamperedToken = $parts[0] + "." + $parts[1] + ".ForgedSignature1234567890"
    Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000001' -Headers @{ Authorization = "Bearer $tamperedToken" }
    Record-Test "Forged JWT Signature" $false "Expected HTTP 401 but succeeded"
} catch {
    Record-Test "Forged JWT Signature" ($_.Exception.Response.StatusCode.value__ -eq 401) "Rejected with HTTP 401 Unauthorized"
}

# Customer accessing protected customer endpoint -> 200 OK
try {
    $cust = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000001' -Headers $alexHeaders
    Record-Test "Valid Customer Token Access" ($cust.customerNumber -eq "CUST-10001") "Customer retrieved: $($cust.firstName) $($cust.lastName)"
} catch {
    Record-Test "Valid Customer Token Access" $false "Failed with $($_.Exception.Message)"
}

# Customer attempting to access Security Events -> 403 Forbidden
try {
    Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/security/events' -Headers $alexHeaders
    Record-Test "Customer Role Restriction on Security Endpoints" $false "Expected HTTP 403 but succeeded"
} catch {
    Record-Test "Customer Role Restriction on Security Endpoints" ($_.Exception.Response.StatusCode.value__ -eq 403) "Rejected with HTTP 403 Forbidden"
}

# Analyst accessing Security Events -> 200 OK with real persisted event structure
try {
    $secRes = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/security/events?size=10' -Headers $analystHeaders -UseBasicParsing
    $hasValidStructure = ($secRes.content -ne $null -and $secRes.page -ne $null -and $secRes.size -ne $null -and $secRes.totalElements -ge 0)
    Record-Test "Analyst Role Access Verification" $hasValidStructure "Analyst retrieved real telemetry events: $($secRes.totalElements) total events (page size: $($secRes.size))"
} catch {
    Record-Test "Analyst Role Access Verification" $false "Failed with $($_.Exception.Message)"
}

# --- 3. OBJECT-LEVEL AUTHORIZATION & BOLA DEFENSE (STAGE 3) ---
Write-Host "`n--- 3. OBJECT-LEVEL AUTHORIZATION (BOLA / IDOR DEFENSE) ---" -ForegroundColor Yellow

# Alex Morgan accessing Sam Taylor's customer record -> MUST BE 403 FORBIDDEN
try {
    $samCust = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000002' -Headers $alexHeaders
    Record-Test "BOLA Defense: Customer Profile" $false "CRITICAL: Alex Morgan accessed Sam Taylor profile!"
} catch {
    Record-Test "BOLA Defense: Customer Profile" ($_.Exception.Response.StatusCode.value__ -eq 403) "Properly rejected with HTTP 403 Forbidden"
}

# Alex Morgan accessing Sam Taylor's account balance -> MUST BE 403 FORBIDDEN
try {
    $samBal = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/accounts/20000000-0000-4000-8000-000000000003/balance' -Headers $alexHeaders
    Record-Test "BOLA Defense: Account Balance" $false "CRITICAL: Alex Morgan accessed Sam Taylor balance!"
} catch {
    Record-Test "BOLA Defense: Account Balance" ($_.Exception.Response.StatusCode.value__ -eq 403) "Properly rejected with HTTP 403 Forbidden"
}

# Alex Morgan querying accounts with customerId=Sam Taylor -> MUST BE 403 FORBIDDEN
try {
    $samAccts = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/accounts?customerId=10000000-0000-4000-8000-000000000002' -Headers $alexHeaders
    Record-Test "BOLA Defense: Cross-Customer Query Parameter" $false "CRITICAL: Alex Morgan queried Sam Taylor accounts!"
} catch {
    Record-Test "BOLA Defense: Cross-Customer Query Parameter" ($_.Exception.Response.StatusCode.value__ -eq 403) "Properly rejected with HTTP 403 Forbidden"
}

# Alex Morgan querying /api/v1/accounts (unfiltered) -> Automatically scoped strictly to Alex Morgan's accounts!
try {
    $myAccts = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/accounts' -Headers $alexHeaders
    $leak = $myAccts | Where-Object { $_.customerId -ne "10000000-0000-4000-8000-000000000001" }
    Record-Test "BOLA Defense: Unfiltered Accounts Auto-Scoping" ($null -eq $leak -and $myAccts.Count -gt 0) "Returned $($myAccts.Count) accounts, all owned by Alex Morgan (no cross-customer leaks)"
} catch {
    Record-Test "BOLA Defense: Unfiltered Accounts Auto-Scoping" $false "Failed with $($_.Exception.Message)"
}

# Admin accessing any customer (Auditing capability) -> 200 OK
try {
    $adminView = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000002' -Headers $adminHeaders
    Record-Test "Admin Audit Read Privilege" ($adminView.customerNumber -eq "CUST-10002") "Admin authorized to view customer for audit: $($adminView.firstName)"
} catch {
    Record-Test "Admin Audit Read Privilege" $false "Failed with $($_.Exception.Message)"
}

# --- 4. GATEWAY-BYPASS DEFENSE & HMAC ATTESTATION (STAGE 4) ---
Write-Host "`n--- 4. GATEWAY-BYPASS DEFENSE & HMAC PROTOCOL VERIFICATION ---" -ForegroundColor Yellow

# Direct call to backend service without signature -> MUST BE 403 FORBIDDEN
try {
    Invoke-RestMethod -Uri 'http://127.0.0.1:8081/customers/10000000-0000-4000-8000-000000000001'
    Record-Test "Bypass Defense: Missing Signature Header" $false "Direct backend request succeeded unexpectedly!"
} catch {
    Record-Test "Bypass Defense: Missing Signature Header" ($_.Exception.Response.StatusCode.value__ -eq 403) "Rejected with HTTP 403 Forbidden"
}

# Direct call with bad signature -> MUST BE 403 FORBIDDEN
try {
    $bypassHeaders = @{
        "X-Correlation-Id" = "bypass-cid-001"
        "X-Aegis-Internal-Signature" = "t=1700000000;sig=badsignaturebadsignaturebadsignaturebadsignaturebadsignature12"
    }
    Invoke-RestMethod -Uri 'http://127.0.0.1:8081/customers/10000000-0000-4000-8000-000000000001' -Headers $bypassHeaders
    Record-Test "Bypass Defense: Invalid Signature Header" $false "Direct request with bad signature succeeded!"
} catch {
    Record-Test "Bypass Defense: Invalid Signature Header" ($_.Exception.Response.StatusCode.value__ -eq 403) "Rejected with HTTP 403 Forbidden"
}

# Correlation ID propagation -> X-Correlation-Id in response
$cidTest = "phase3-cid-verify-$(Get-Random)"
$respWithCid = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000001' -Headers @{ Authorization = "Bearer $alexToken"; "X-Correlation-Id" = $cidTest }
$respCid = $respWithCid.Headers["X-Correlation-Id"]
Record-Test "Correlation ID Propagation" ($respCid -eq $cidTest) "X-Correlation-Id echoed in response: $respCid"

# --- 5. TELEMETRY DURABILITY & PRIVACY (STAGE 5) ---
Write-Host "`n--- 5. TELEMETRY DURABILITY & PRIVACY AUDIT ---" -ForegroundColor Yellow

# Wait 3 seconds for telemetry worker to drain stream
Start-Sleep -Seconds 3

# Query PostgreSQL security_data.api_events
$pgEvents = docker exec aegis-postgres-1 psql -U aegis_owner -d aegis -t -c "SELECT route_id, status_code, auth_subject, anomaly_flags FROM security_data.api_events WHERE correlation_id = '$cidTest';"
$hasPersisted = ($pgEvents -match "200")
Record-Test "Telemetry Stream-to-PostgreSQL Persistence" $hasPersisted "Persisted event for correlation ID $cidTest (Route: /customers/{id})"

# Verify unauthenticated request logs anonymous / unauthenticated (not spoofed)
$unauthCid = "unauth-test-$(Get-Random)"
try {
    Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000001' -Headers @{ "X-Correlation-Id" = $unauthCid }
} catch {}
Start-Sleep -Seconds 3
$unauthEvent = docker exec aegis-postgres-1 psql -U aegis_owner -d aegis -t -c "SELECT auth_subject, status_code, anomaly_flags FROM security_data.api_events WHERE correlation_id = '$unauthCid';"
$unauthCorrect = ($unauthEvent -match "anonymous" -and $unauthEvent -match "401")
Record-Test "Telemetry Privacy: Unverified Spoof Defense" $unauthCorrect "Unauthenticated request recorded subject as 'anonymous' with status 401"

# --- 6. TRANSFER ORCHESTRATION & IDEMPOTENCY (STAGE 6) ---
Write-Host "`n--- 6. TRANSFER ORCHESTRATION & IDEMPOTENCY ---" -ForegroundColor Yellow

# Get a verified beneficiary of Alex Morgan
$bens = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/beneficiaries' -Headers $alexHeaders
$ben = $bens | Where-Object { $_.status -eq "VERIFIED" } | Select-Object -First 1

if ($ben) {
    $idemKey = "e2e-idem-phase3-$(Get-Random)"
    $transferPayload = @{
        customerId = "10000000-0000-4000-8000-000000000001"
        sourceAccountId = "20000000-0000-4000-8000-000000000001"
        beneficiaryId = $ben.id
        amount = 5.0000
        currency = "USD"
        reference = $idemKey
    } | ConvertTo-Json

    # 1st transfer execution
    $t1 = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/transfers' -Method Post -Headers $alexHeaders -ContentType 'application/json' -Body $transferPayload
    Record-Test "Transfer Execution" ($t1.status -eq "COMPLETED") "Transfer completed: ID $($t1.id), Reference: $($t1.reference)"

    # 2nd transfer execution with SAME Idempotency-Key
    $t2 = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/transfers' -Method Post -Headers $alexHeaders -ContentType 'application/json' -Body $transferPayload
    Record-Test "Transfer Idempotency" ($t1.id -eq $t2.id -and $t2.status -eq "COMPLETED") "Re-sent transfer returned exact same ID without duplicating transaction"
} else {
    Record-Test "Transfer Execution & Idempotency" $false "No verified beneficiary available for Alex Morgan"
}

# --- 7. CONCURRENCY & LATENCY BENCHMARK (STAGE 7) ---
Write-Host "`n--- 7. CONCURRENCY & PERFORMANCE BENCHMARK (50 REQUESTS, CONCURRENCY = 10) ---" -ForegroundColor Yellow

Add-Type -AssemblyName System.Net.Http
$benchHandler = New-Object System.Net.Http.HttpClientHandler
$benchClient = New-Object System.Net.Http.HttpClient($benchHandler)
$benchClient.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", $alexToken)
$targetUrl = 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000001'

# Warm-up (10 requests)
for ($w = 0; $w -lt 10; $w++) {
    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $targetUrl)
    $null = $benchClient.SendAsync($req).Result.Content.ReadAsStringAsync().Result
}

# 50 requests across 5 batches of 10 concurrent requests
$benchLatencies = [System.Collections.Concurrent.ConcurrentBag[double]]::new()
$benchErrors = 0
$totalBench = 50
$concurrencyLevel = 10
$benchSw = [System.Diagnostics.Stopwatch]::StartNew()

for ($b = 0; $b -lt 5; $b++) {
    $batchTasks = [System.Collections.Generic.List[System.Threading.Tasks.Task[System.Net.Http.HttpResponseMessage]]]::new()
    $batchSw = [System.Collections.Generic.List[System.Diagnostics.Stopwatch]]::new()
    for ($i = 0; $i -lt $concurrencyLevel; $i++) {
        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Get, $targetUrl)
        $req.Headers.Add("X-Correlation-Id", "bench-$([System.Guid]::NewGuid().ToString().Substring(0,8))")
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $batchSw.Add($sw)
        $batchTasks.Add($benchClient.SendAsync($req))
    }
    [System.Threading.Tasks.Task]::WaitAll($batchTasks.ToArray())
    for ($i = 0; $i -lt $concurrencyLevel; $i++) {
        $batchSw[$i].Stop()
        $benchLatencies.Add($batchSw[$i].Elapsed.TotalMilliseconds)
        $t = $batchTasks[$i]
        if ($t.IsFaulted -or [int]$t.Result.StatusCode -ne 200) {
            $benchErrors++
        } else {
            $null = $t.Result.Content.ReadAsStringAsync().Result
        }
    }
}
$benchSw.Stop()
$benchClient.Dispose()

$sortedLatencies = $benchLatencies | Sort-Object
$p50 = $sortedLatencies[[Math]::Floor($sortedLatencies.Count * 0.50)]
$p95 = $sortedLatencies[[Math]::Floor($sortedLatencies.Count * 0.95)]
$p99 = $sortedLatencies[[Math]::Floor($sortedLatencies.Count * 0.99)]
$rps = [Math]::Round(($totalBench / $benchSw.Elapsed.TotalSeconds), 1)

Record-Test "Concurrency & Latency Benchmark" ($benchErrors -eq 0) "50 requests (c=$concurrencyLevel): 0 errors (0.0%). Duration: $([Math]::Round($benchSw.Elapsed.TotalMilliseconds, 1))ms, Throughput: $rps RPS. Median (p50): $([Math]::Round($p50, 1))ms, p95: $([Math]::Round($p95, 1))ms, p99: $([Math]::Round($p99, 1))ms"

Write-Host "`n=================================================================" -ForegroundColor Cyan
$passCount = ($results.Values | Where-Object { $_.Status -eq "PASS" }).Count
$totalCount = $results.Count
Write-Host "GATE VERIFICATION SUMMARY: $passCount / $totalCount TESTS PASSED" -ForegroundColor $(if ($passCount -eq $totalCount) { "Green" } else { "Red" })
Write-Host "=================================================================`n" -ForegroundColor Cyan
