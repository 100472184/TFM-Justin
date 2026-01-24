param(
    [Parameter(Mandatory=$true)]
    [string]$SeedPath,
    [Parameter(Mandatory=$false)]
    [string]$TaskId = "CVE-2024-57970_libarchive"
)

$taskPath = "tasks/$TaskId/compose.yml"

function Test-Seed {
    param([int]$TestNum)
    
    Write-Host "`n=== Test $TestNum - Vulnerable ===" -ForegroundColor Cyan
    docker compose -f $taskPath down --volumes | Out-Null
    $vuln = python -m scripts.bench run $TaskId --service target-vuln --seed $SeedPath
    Write-Host $vuln
    
    Write-Host "`n=== Test $TestNum - Fixed ===" -ForegroundColor Green  
    docker compose -f $taskPath down --volumes | Out-Null
    $fixed = python -m scripts.bench run $TaskId --service target-fixed --seed $SeedPath
    Write-Host $fixed
}

# Run 3 tests
Test-Seed -TestNum 1
Test-Seed -TestNum 2
Test-Seed -TestNum 3

# Final cleanup
docker compose -f $taskPath down --volumes | Out-Null
Write-Host "`nAll tests should show IDENTICAL exit codes" -ForegroundColor Yellow
Write-Host "Expected for valid exploit: vuln=139, fixed=0 or 1" -ForegroundColor Yellow
