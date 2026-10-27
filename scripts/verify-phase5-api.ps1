[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  AEGIS PHASE 5.2 - SECURITY OPERATIONS BACKEND APIS GATE        " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Record-Test($name, $passed, $details) {
    $result = if ($passed) { "[PASS]" } else { "[FAIL]" }
    $color = if ($passed) { "Green" } else { "Red" }
    Write-Host "$result $name - $details" -ForegroundColor $color
    $testResults.Add([PSCustomObject]@{
        Name    = $name
        Passed  = $passed
        Details = $details
    })
    if (-not $passed) {
        Write-Error "Verification failed on: $name - $details"
    }
}

function Call-Api($uri, $authHeaders, $method = "Get", $body = $null) {
    try {
        $params = @{
            Uri     = $uri
            Headers = $authHeaders
            Method  = $method
        }
        if ($body) {
            $params["Body"] = $body
            $params["ContentType"] = "application/json"
        }
        $res = Invoke-RestMethod @params
        return [PSCustomObject]@{
            StatusCode = 200
            Data       = $res
            Headers    = $null
        }
    } catch {
        $code = 500
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $code = [int]$_.Exception.Response.StatusCode
        }
        $bodyContent = $null
        if ($_.Exception.Response) {
            $stream = $_.Exception.Response.GetResponseStream()
            if ($stream) {
                $reader = [System.IO.StreamReader]::new($stream)
                $rawBody = $reader.ReadToEnd()
                try {
                    $bodyContent = $rawBody | ConvertFrom-Json
                } catch {
                    $bodyContent = $rawBody
                }
            }
        }
        return [PSCustomObject]@{
            StatusCode = $code
            Data       = $bodyContent
            Headers    = $null
        }
    }
}

# --- 1. ACQUIRING TOKENS FROM KEYCLOAK ---
Write-Host "`n--- 1. ACQUIRING TOKENS FROM REAL KEYCLOAK ---" -ForegroundColor Yellow

$alexBody = @{ client_id = 'aegis-local'; username = 'alex.morgan'; password = 'Password123!'; grant_type = 'password' }
$alexTokenRes = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/realms/aegis-dev/protocol/openid-connect/token' -Method Post -Body $alexBody
$alexToken = $alexTokenRes.access_token
$alexHeaders = @{ Authorization = "Bearer $alexToken" }
$alexCustomerId = '10000000-0000-4000-8000-000000000001'

$analystBody = @{ client_id = 'aegis-local'; username = 'analyst'; password = 'Password123!'; grant_type = 'password' }
$analystTokenRes = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/realms/aegis-dev/protocol/openid-connect/token' -Method Post -Body $analystBody
$analystToken = $analystTokenRes.access_token
$analystHeaders = @{ Authorization = "Bearer $analystToken" }

$adminBody = @{ client_id = 'aegis-local'; username = 'admin'; password = 'Password123!'; grant_type = 'password' }
$adminTokenRes = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/realms/aegis-dev/protocol/openid-connect/token' -Method Post -Body $adminBody
$adminToken = $adminTokenRes.access_token
$adminHeaders = @{ Authorization = "Bearer $adminToken" }

Record-Test "Keycloak Token Acquisition" ($alexToken -ne $null -and $analystToken -ne $null -and $adminToken -ne $null) "Acquired tokens for alex.morgan, analyst, and admin"

# --- 2. PREPARING TELEMETRY & TRIGGERING REAL INCIDENT ---
Write-Host "`n--- 2. TRIGGERING REAL DETECTION TO POPULATE TELEMETRY & INCIDENTS ---" -ForegroundColor Yellow

# Clean state
docker exec aegis-postgres-1 psql -U aegis_owner -d aegis -c "TRUNCATE security_data.detection_evidence, security_data.incident_status_history, security_data.policy_decisions, security_data.incidents, security_data.api_events CASCADE;" | Out-Null
docker exec aegis-redis-1 redis-cli eval "for _,k in ipairs(redis.call('keys','aegis:state:*')) do redis.call('del',k) end" 0 | Out-Null

# Send legitimate traffic
$null = Call-Api "http://127.0.0.1:8000/api/v1/customers/$alexCustomerId" $alexHeaders
$null = Call-Api "http://127.0.0.1:8000/api/v1/accounts?customerId=$alexCustomerId" $alexHeaders

# Send 3 unauthorized cross-customer probing requests (triggers RULE-BOLA-01)
$targets = @('10000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000004')
foreach ($t in $targets) {
    $null = Call-Api "http://127.0.0.1:8000/api/v1/customers/$t" $alexHeaders
    Start-Sleep -Milliseconds 100
}

# Wait for stream processing, correlation, and telemetry drain
Write-Host "Awaiting detection engine and telemetry drain processing..." -ForegroundColor DarkGray
$detectedIncidentId = $null
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 500
    $incRaw = (docker exec aegis-postgres-1 psql -U aegis_owner -d aegis -t -A -c "SELECT id FROM security_data.incidents LIMIT 1;") | Out-String
    $eventCountRaw = (docker exec aegis-postgres-1 psql -U aegis_owner -d aegis -t -A -c "SELECT count(*) FROM security_data.api_events;") | Out-String
    $eventCount = 0
    if ($eventCountRaw) { [int]::TryParse($eventCountRaw.Trim(), [ref]$eventCount) | Out-Null }
    if ($incRaw -and $incRaw.Trim().Length -gt 10 -and $eventCount -ge 5) {
        $detectedIncidentId = $incRaw.Trim()
        break
    }
}
Record-Test "Threat Detection Pipeline" ($detectedIncidentId -ne $null) "Incident persisted in PostgreSQL: $detectedIncidentId"

# --- 3. ENDPOINT 1: SECURITY OVERVIEW METRICS ---
Write-Host "`n--- 3. VERIFYING SECURITY OVERVIEW METRICS ---" -ForegroundColor Yellow

# 3.1 Unauthenticated -> 401
$ovUnauth = Call-Api "http://127.0.0.1:8000/api/v1/security/overview" @{}
Record-Test "Overview RBAC: Unauthenticated" ($ovUnauth.StatusCode -eq 401) "Rejected with 401 Unauthorized"

# 3.2 Customer -> 403
$ovCustomer = Call-Api "http://127.0.0.1:8000/api/v1/security/overview" $alexHeaders
Record-Test "Overview RBAC: Customer Denied" ($ovCustomer.StatusCode -eq 403) "Rejected with 403 Forbidden"

# 3.3 Invalid windowHours -> 400
$ovBadWindow = Call-Api "http://127.0.0.1:8000/api/v1/security/overview?windowHours=200" $analystHeaders
Record-Test "Overview Validation: Window Bounds" ($ovBadWindow.StatusCode -eq 400) "windowHours=200 rejected with 400 Bad Request"

# 3.4 Security Analyst -> 200 OK with real aggregated metrics
$ovSuccess = Call-Api "http://127.0.0.1:8000/api/v1/security/overview?windowHours=24" $analystHeaders
$ovData = $ovSuccess.Data
$hasOverviewFields = ($ovSuccess.StatusCode -eq 200) -and
                     ($ovData.totalEvents -ge 5) -and
                     ($ovData.totalAnomalies -ge 3) -and
                     ($ovData.openIncidents -ge 1) -and
                     ($ovData.incidentsBySeverity.HIGH -ge 1 -or $ovData.incidentsBySeverity.CRITICAL -ge 1) -and
                     ($ovData.recentIncidents.Count -ge 1) -and
                     ($ovData.topTriggeredRules.Count -ge 1) -and
                     ($ovData.timeSeriesTrend -ne $null)
Record-Test "Overview Metrics: Real Aggregation" $hasOverviewFields "Events=$($ovData.totalEvents), Anomalies=$($ovData.totalAnomalies), OpenIncidents=$($ovData.openIncidents), TopRule=$($ovData.topTriggeredRules[0].ruleId)"

# --- 4. ENDPOINT 2: ENHANCED EVENT SEARCH & DETAIL ---
Write-Host "`n--- 4. VERIFYING ENHANCED EVENT SEARCH & DETAIL APIS ---" -ForegroundColor Yellow

# 4.1 Filter by statusCode=403
$events403 = Call-Api "http://127.0.0.1:8000/api/v1/security/events?statusCode=403" $analystHeaders
$firstEventId = if ($events403.Data.content.Count -gt 0) { $events403.Data.content[0].id } else { $null }
Record-Test "Event Search: Filter by statusCode=403" ($events403.StatusCode -eq 200 -and $events403.Data.content.Count -ge 3) "Found $($events403.Data.content.Count) events with HTTP 403"

# 4.2 Filter by customerId
$eventsCustomer = Call-Api "http://127.0.0.1:8000/api/v1/security/events?customerId=$alexCustomerId" $analystHeaders
Record-Test "Event Search: Filter by customerId" ($eventsCustomer.StatusCode -eq 200 -and $eventsCustomer.Data.totalElements -ge 5) "Scoped $($eventsCustomer.Data.totalElements) events to Alex"

# 4.3 Filter by anomalyFlags
$eventsAnomaly = Call-Api "http://127.0.0.1:8000/api/v1/security/events?anomalyFlags=FORBIDDEN" $analystHeaders
Record-Test "Event Search: Filter by anomalyFlags" ($eventsAnomaly.StatusCode -eq 200 -and $eventsAnomaly.Data.content.Count -ge 3) "Retrieved $($eventsAnomaly.Data.content.Count) anomaly events"

# 4.4 Date range validation: from after to -> 400
$nowIso = [System.DateTime]::UtcNow.ToString("o")
$pastIso = [System.DateTime]::UtcNow.AddHours(-1).ToString("o")
$eventsBadDate = Call-Api "http://127.0.0.1:8000/api/v1/security/events?from=$nowIso&to=$pastIso" $analystHeaders
Record-Test "Event Search Validation: Inverted Date Range" ($eventsBadDate.StatusCode -eq 400) "Inverted time range rejected with 400 Bad Request"

# 4.5 Single Event Detail lookup
$singleEvent = Call-Api "http://127.0.0.1:8000/api/v1/security/events/$firstEventId" $analystHeaders
$singleEventValid = ($singleEvent.StatusCode -eq 200) -and
                    ($singleEvent.Data.id -eq $firstEventId) -and
                    ($singleEvent.Data.resourceType -eq "CUSTOMER") -and
                    ($singleEvent.Data.errorCode -eq "BOLA_VIOLATION")
Record-Test "Single Event Detail: GET /events/{id}" $singleEventValid "Retrieved event $firstEventId with resourceType=CUSTOMER and errorCode=BOLA_VIOLATION"

# 4.6 Missing Event Detail lookup -> 404
$randomEventId = [System.Guid]::NewGuid().ToString()
$missingEvent = Call-Api "http://127.0.0.1:8000/api/v1/security/events/$randomEventId" $analystHeaders
Record-Test "Single Event Detail: Missing ID 404" ($missingEvent.StatusCode -eq 404) "Non-existent event ID rejected with 404 Not Found"

# --- 5. ENDPOINT 3: INCIDENT LISTING & INVESTIGATION ---
Write-Host "`n--- 5. VERIFYING INCIDENT LISTING & INVESTIGATION APIS ---" -ForegroundColor Yellow

# 5.1 Listing incidents with pagination
$incidentsList = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents?page=0&size=10" $analystHeaders
Record-Test "Incident Listing: Paginated GET /incidents" ($incidentsList.StatusCode -eq 200 -and $incidentsList.Data.content.Count -ge 1) "Returned $($incidentsList.Data.content.Count) incidents (total: $($incidentsList.Data.totalElements))"

# 5.2 Filter by status=OPEN
$incidentsOpen = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents?status=OPEN" $analystHeaders
Record-Test "Incident Listing: Filter by status=OPEN" ($incidentsOpen.StatusCode -eq 200 -and $incidentsOpen.Data.content.Count -ge 1) "Filtered $($incidentsOpen.Data.content.Count) OPEN incidents"

# 5.3 Single incident lookup
$singleInc = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId" $analystHeaders
Record-Test "Single Incident Lookup: GET /incidents/{id}" ($singleInc.StatusCode -eq 200 -and $singleInc.Data.id -eq $detectedIncidentId) "Incident verified: fingerprint=$($singleInc.Data.incidentFingerprint), rule=$($singleInc.Data.ruleId)"

# 5.4 Missing incident lookup -> 404
$randomIncId = [System.Guid]::NewGuid().ToString()
$missingInc = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$randomIncId" $analystHeaders
Record-Test "Single Incident Lookup: Missing ID 404" ($missingInc.StatusCode -eq 404) "Non-existent incident ID rejected with 404 Not Found"

# --- 6. ENDPOINT 4: INCIDENT EVIDENCE & CORRELATION ---
Write-Host "`n--- 6. VERIFYING INCIDENT EVIDENCE & CORRELATION APIS ---" -ForegroundColor Yellow

$evidenceRes = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/evidence" $analystHeaders
$evidenceValid = ($evidenceRes.StatusCode -eq 200) -and
                 ($evidenceRes.Data.Count -ge 1) -and
                 ($evidenceRes.Data[0].incidentId -eq $detectedIncidentId) -and
                 ($evidenceRes.Data[0].confidenceScore -ge 0.90) -and
                 ($evidenceRes.Data[0].contributingEventIds.Count -ge 3)
Record-Test "Incident Evidence: GET /incidents/{id}/evidence" $evidenceValid "Evidence count=$($evidenceRes.Data.Count), Rule=$($evidenceRes.Data[0].ruleId), ContributingEvents=$($evidenceRes.Data[0].contributingEventIds.Count)"

$missingEvidence = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$randomIncId/evidence" $analystHeaders
Record-Test "Incident Evidence: Missing Incident 404" ($missingEvidence.StatusCode -eq 404) "Evidence query for missing incident rejected with 404 Not Found"

# --- 7. ENDPOINT 5: INCIDENT LIFECYCLE & AUDIT HISTORY ---
Write-Host "`n--- 7. VERIFYING INCIDENT LIFECYCLE & AUDIT HISTORY APIS ---" -ForegroundColor Yellow

# 7.1 Transition OPEN -> INVESTIGATING by analyst
$patchBody1 = @{
    status = "INVESTIGATING"
    reason = "Analyst assigned to review cross-customer probing activity"
} | ConvertTo-Json

$patchRes1 = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/status" $analystHeaders "Patch" $patchBody1
Record-Test "Incident Lifecycle: OPEN -> INVESTIGATING" ($patchRes1.StatusCode -eq 200 -and $patchRes1.Data.status -eq "INVESTIGATING") "Updated status to INVESTIGATING by analyst"

# 7.2 Verify status history audit entry
$histRes1 = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/history" $analystHeaders
$histEntry = $histRes1.Data | Where-Object { $_.newStatus -eq "INVESTIGATING" }
$historyValid = ($histEntry -ne $null) -and ($histEntry.previousStatus -eq "OPEN") -and ($histEntry.changedBy -eq "analyst")
Record-Test "Incident History Audit Trail: JWT Actor Attribution" $historyValid "Audit record verified: previous=OPEN, new=INVESTIGATING, changedBy=$($histEntry.changedBy)"

# 7.3 Transition INVESTIGATING -> RESOLVED by analyst
$patchBody2 = @{
    status = "RESOLVED"
    reason = "Incident confirmed as unauthorized attempt; customer credential reset advisory dispatched"
} | ConvertTo-Json

$patchRes2 = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/status" $analystHeaders "Patch" $patchBody2
Record-Test "Incident Lifecycle: INVESTIGATING -> RESOLVED" ($patchRes2.StatusCode -eq 200 -and $patchRes2.Data.status -eq "RESOLVED") "Incident moved to terminal status RESOLVED"

# 7.4 Analyst attempts to reopen terminal RESOLVED incident -> 403 Forbidden
$patchBodyReopen = @{
    status = "INVESTIGATING"
    reason = "Analyst trying to reopen terminal incident"
} | ConvertTo-Json

$patchAnalystReopen = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/status" $analystHeaders "Patch" $patchBodyReopen
Record-Test "Terminal Reopen Defense: Analyst Forbidden (403)" ($patchAnalystReopen.StatusCode -eq 403) "Analyst prohibited from reopening terminal incident (403 Forbidden)"

# 7.5 Admin reopens terminal RESOLVED incident to INVESTIGATING -> 200 OK
$patchBodyAdmin = @{
    status = "INVESTIGATING"
    reason = "Security Admin approved reopening for advanced multi-vector correlation analysis"
} | ConvertTo-Json

$patchAdminReopen = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/status" $adminHeaders "Patch" $patchBodyAdmin
Record-Test "Terminal Reopen Privilege: Admin Reopening (200)" ($patchAdminReopen.StatusCode -eq 200 -and $patchAdminReopen.Data.status -eq "INVESTIGATING") "Security Admin reopened resolved incident to INVESTIGATING"

# 7.6 Invalid transition attempt (e.g. self-transition) -> 409 Conflict
$patchBodyInvalid = @{
    status = "INVESTIGATING"
    reason = "Attempting redundant transition to current status"
} | ConvertTo-Json

$patchConflict = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/status" $adminHeaders "Patch" $patchBodyInvalid
Record-Test "State Machine Defense: Conflict on Invalid Transition (409)" ($patchConflict.StatusCode -eq 409) "Invalid transition rejected with 409 Conflict"

# 7.7 Validation check: Reason < 5 characters -> 400 Bad Request
$patchBodyShort = @{
    status = "CONTAINED"
    reason = "bad"
} | ConvertTo-Json

$patchShort = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/status" $adminHeaders "Patch" $patchBodyShort
Record-Test "Status Update Validation: Short Reason (400)" ($patchShort.StatusCode -eq 400) "Reason with 3 characters rejected with 400 Bad Request"

# --- 8. ENDPOINT 6: ADVISORY POLICY DECISIONS ---
Write-Host "`n--- 8. VERIFYING ADVISORY POLICY DECISIONS APIS ---" -ForegroundColor Yellow

# 8.1 Incident specific policy decisions
$policiesInc = Call-Api "http://127.0.0.1:8000/api/v1/security/incidents/$detectedIncidentId/policy-decisions" $analystHeaders
$hasPolicy = ($policiesInc.StatusCode -eq 200) -and
             ($policiesInc.Data.Count -ge 1) -and
             ($policiesInc.Data[0].recommendedAction -eq "LOG_ALERT") -and
             ($policiesInc.Data[0].enforcementLevel -eq "ADVISORY")
Record-Test "Incident Policy Decisions: GET /incidents/{id}/policy-decisions" $hasPolicy "Retrieved policy decision: Action=$($policiesInc.Data[0].recommendedAction), Level=$($policiesInc.Data[0].enforcementLevel)"

# 8.2 Global recent policy decisions
$policiesGlobal = Call-Api "http://127.0.0.1:8000/api/v1/security/policy-decisions" $analystHeaders
Record-Test "Global Policy Decisions: GET /policy-decisions" ($policiesGlobal.StatusCode -eq 200 -and $policiesGlobal.Data.Count -ge 1) "Retrieved $($policiesGlobal.Data.Count) global policy decisions"

# 8.3 Advisory Invariant Verification: Zero client disruption
$legitSelf = Call-Api "http://127.0.0.1:8000/api/v1/customers/$alexCustomerId" $alexHeaders
Record-Test "Advisory Invariant: Zero Disruptive Client Blocking" ($legitSelf.StatusCode -eq 200) "Customer self-access remains fully operational (HTTP 200 OK)"

# --- SUMMARY & ACCEPTANCE GATE ---
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "  PHASE 5.2 BACKEND SOC APIS GATE SUMMARY                        " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$totalTests = $testResults.Count
$passedTests = ($testResults | Where-Object { $_.Passed }).Count
$failedTests = $totalTests - $passedTests

Write-Host "Total Tests  : $totalTests"
Write-Host "Passed Tests : $passedTests" -ForegroundColor Green
if ($failedTests -gt 0) {
    Write-Host "Failed Tests : $failedTests" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All $totalTests verification tests passed successfully!" -ForegroundColor Green
    Write-Host "=================================================================" -ForegroundColor Cyan
    exit 0
}
