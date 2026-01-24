# Correct Testing Workflow

## Complete Test Procedure (with cleanup)

### 1. Initial Clean Start

```powershell
# Remove all Docker state
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes --rmi all
docker system prune -af --volumes

# Rebuild images
python -m scripts.bench build CVE-2024-57970_libarchive

# Verify images are correct
docker run --rm --entrypoint /opt/target/bin/bsdtar cve-2024-57970_libarchive-target-vuln --version
# Expected: bsdtar 3.7.7 - libarchive 3.7.7

docker run --rm --entrypoint /opt/target/bin/bsdtar cve-2024-57970_libarchive-target-fixed --version
# Expected: bsdtar 3.7.8 - libarchive 3.7.8
```

### 2. Run Pipeline Test

```powershell
# Run pipeline (this now includes automatic cleanup before/after each iteration)
python -m agents.openhands_llama3.run --task-id CVE-2024-57970_libarchive --level L3 --max-iters 10

# If success reported, note the iteration number (e.g., iter_007)
```

### 3. Manual Verification (if crash detected)

```powershell
# CRITICAL: Clean Docker state before manual test
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
docker network ls | Select-String "cve-2024"  # Should show NOTHING

# Test vulnerable version manually
python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed "runs\<TIMESTAMP>\CVE-2024-57970_libarchive\iter_XXX\mutated_seed_itXX.bin"
# Expected if valid exploit: exit_code=139 or ASan output

# Clean again before testing fixed version
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes

# Test fixed version
python -m scripts.bench run CVE-2024-57970_libarchive --service target-fixed --seed "runs\<TIMESTAMP>\CVE-2024-57970_libarchive\iter_XXX\mutated_seed_itXX.bin"
# Expected: exit_code=0 or exit_code=1 (no crash)

# Clean after manual tests
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
```

### 4. Run Evaluate Command

```powershell
# CRITICAL: Clean Docker state before evaluate
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
docker network ls | Select-String "cve-2024"  # Should show NOTHING

# Run evaluate (tests both versions in sequence)
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed "runs\<TIMESTAMP>\CVE-2024-57970_libarchive\iter_XXX\mutated_seed_itXX.bin"
# Expected if valid: vuln_crashes=True fixed_crashes=False success=True

# Clean after evaluate
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
```

### 5. Verify Consistency (Run Multiple Times)

```powershell
# Clean before each run
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes

# Run 1
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed "runs\<TIMESTAMP>\CVE-2024-57970_libarchive\iter_XXX\mutated_seed_itXX.bin"

# Clean
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes

# Run 2
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed "runs\<TIMESTAMP>\CVE-2024-57970_libarchive\iter_XXX\mutated_seed_itXX.bin"

# Clean
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes

# Run 3
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed "runs\<TIMESTAMP>\CVE-2024-57970_libarchive\iter_XXX\mutated_seed_itXX.bin"

# All three runs should give IDENTICAL results
```

## Quick Reference Commands

### Clean Docker State (use between ALL tests)
```powershell
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
```

### Check if Network Still Exists (should be empty)
```powershell
docker network ls | Select-String "cve-2024"
```

### Force Remove Network (if still exists)
```powershell
docker network rm cve-2024-57970_libarchive_default
```

### Test Known Exploit (base_truncated.tar)
```powershell
# Clean first
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes

# Test
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed "tasks\CVE-2024-57970_libarchive\seeds\base_truncated.tar"
# Expected: vuln_crashes=True fixed_crashes=False success=True

# Clean after
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
```

## Common Mistakes to AVOID

❌ **Running tests back-to-back without cleanup:**
```powershell
# WRONG - will give inconsistent results
python -m scripts.bench evaluate ... 
python -m scripts.bench evaluate ...  # Different result!
```

✅ **Correct - clean between each test:**
```powershell
# RIGHT - consistent results
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
python -m scripts.bench evaluate ...
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
python -m scripts.bench evaluate ...  # Same result
```

❌ **Forgetting to check network removal:**
```powershell
docker compose down --volumes
# Network might still exist!
```

✅ **Correct - verify network is gone:**
```powershell
docker compose down --volumes
docker network ls | Select-String "cve-2024"  # Should be empty
```

## Automated Test Script

Save this as `test_seed.ps1`:

```powershell
param(
    [Parameter(Mandatory=$true)]
    [string]$SeedPath
)

$taskPath = "tasks/CVE-2024-57970_libarchive/compose.yml"

Write-Host "`n=== Test 1 ===" -ForegroundColor Cyan
docker compose -f $taskPath down --volumes | Out-Null
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed $SeedPath

Write-Host "`n=== Test 2 ===" -ForegroundColor Cyan
docker compose -f $taskPath down --volumes | Out-Null
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed $SeedPath

Write-Host "`n=== Test 3 ===" -ForegroundColor Cyan
docker compose -f $taskPath down --volumes | Out-Null
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed $SeedPath

# Final cleanup
docker compose -f $taskPath down --volumes | Out-Null
Write-Host "`nAll three tests should show IDENTICAL results" -ForegroundColor Yellow
```

Usage:
```powershell
.\test_seed.ps1 "runs\20260124_XXX\CVE-2024-57970_libarchive\iter_007\mutated_seed_it07.bin"
```

## Why This Workflow is Necessary

1. **Docker Compose doesn't propagate exit codes** - the fixes in bench.py now handle this, but cleanup is still critical

2. **Networks persist between runs** - the network `cve-2024-57970_libarchive_default` stays alive and affects subsequent tests

3. **Volumes can cache state** - `--volumes` flag removes persistent data

4. **False positives come from stale state** - cleaning between tests prevents this

## Expected Behavior After Fixes

✅ Same seed → Same result (deterministic)
✅ Manual test → Same as subprocess call
✅ Pipeline verify.json → Matches manual validation
✅ No persistent networks between tests
✅ Exit codes correctly propagated from container
