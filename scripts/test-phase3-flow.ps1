$ErrorActionPreference = 'Stop'

Write-Host "=== 1. ACQUIRING TOKEN FROM KEYCLOAK FOR alex.morgan ===" -ForegroundColor Cyan
$tokenBody = @{
    client_id     = 'aegis-local'
    username      = 'alex.morgan'
    password      = 'Password123!'
    grant_type    = 'password'
}
$tokenResponse = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/realms/aegis-dev/protocol/openid-connect/token' -Method Post -Body $tokenBody
$token = $tokenResponse.access_token
Write-Host "Token successfully acquired! (expires_in: $($tokenResponse.expires_in)s)" -ForegroundColor Green

$headers = @{
    Authorization   = "Bearer $token"
    "X-Correlation-Id" = "test-phase3-$(Get-Random)"
}

Write-Host "`n=== 2. CALLING GATEWAY: GET /api/v1/customers/10000000-0000-4000-8000-000000000001 ===" -ForegroundColor Cyan
$cust = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/customers/10000000-0000-4000-8000-000000000001' -Headers $headers
$cust | ConvertTo-Json

Write-Host "`n=== 3. CALLING GATEWAY: GET /api/v1/accounts?customerId=10000000-0000-4000-8000-000000000001 ===" -ForegroundColor Cyan
$accounts = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/accounts?customerId=10000000-0000-4000-8000-000000000001' -Headers $headers
$accounts | ConvertTo-Json

Write-Host "`n=== 4. CALLING GATEWAY: GET /api/v1/beneficiaries ===" -ForegroundColor Cyan
$bens = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/v1/beneficiaries' -Headers $headers
$bens | ConvertTo-Json

Write-Host "`n=== 5. CHECKING DIRECT ACCESS REJECTION (GATEWAY BYPASS DEFENSE) ===" -ForegroundColor Cyan
try {
    Invoke-RestMethod -Uri 'http://127.0.0.1:8081/customers/10000000-0000-4000-8000-000000000001'
    Write-Host "ERROR: Bypass succeeded unexpectedly!" -ForegroundColor Red
} catch {
    Write-Host "Successfully rejected with HTTP $($_.Exception.Response.StatusCode.value__):" -ForegroundColor Green
    $stream = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($stream)
    Write-Host $reader.ReadToEnd()
}

Write-Host "`n=== PHASE 3 END-TO-END GATEWAY FLOW VERIFIED ===" -ForegroundColor Green
