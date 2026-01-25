# Correct Testing Workflow

## Complete Test Procedure (with cleanup)

### 1. Initial Clean Start

```powershell
# Remove all Docker state
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes --rmi all
docker system prune -af --volumes

# Rebuild images
python -m scripts.bench build CVE-2024-57970_libarchive

# CRITICAL: Verify images are ready (may need 2-10 attempts, keep retrying!)
# Run this command REPEATEDLY until you see version output:
docker run --rm --entrypoint /opt/target/bin/bsdtar cve-2024-57970_libarchive-target-vuln --version
# Expected (after 2-10 tries): bsdtar 3.7.7 - libarchive 3.7.7

# Run this command REPEATEDLY until you see version output:
docker run --rm --entrypoint /opt/target/bin/bsdtar cve-2024-57970_libarchive-target-fixed --version
# Expected (after 2-10 tries): bsdtar 3.7.8 - libarchive 3.7.8

# DO NOT PROCEED until BOTH commands return version output!
```

**⚠️ CRITICAL**: The `docker run --version` commands will return EMPTY output on first attempts. This is NORMAL. Simply run the SAME command again (and again) until you see the version. Typical pattern:
```powershell
PS> docker run --rm --entrypoint /opt/target/bin/bsdtar cve-2024-57970_libarchive-target-vuln --version
(empty)
PS> docker run --rm --entrypoint /opt/target/bin/bsdtar cve-2024-57970_libarchive-target-vuln --version
(empty)
PS> docker run --rm --entrypoint /opt/target/bin/bsdtar cve-2024-57970_libarchive-target-vuln --version
(empty)
PS> docker run --rm --entrypoint /opt/target/bin/bsdtar cve-2024-57970_libarchive-target-vuln --version
bsdtar 3.7.7 - libarchive 3.7.7 zlib/1.2.11 liblzma/5.2.5 bz2lib/1.0.8 libzstd/1.4.8
```

**TIP**: Use `test_workflow.py` script which does infinite retry automatically:
```powershell
python test_workflow.py
# Will show: "○ Attempt 1: (no output, retrying...)"
#            "○ Attempt 2: (no output, retrying...)"
#            "✓ Attempt 4: SUCCESS"
```

### 2. Run Pipeline Test

```powershell
# Run pipeline (this now includes automatic cleanup before/after each iteration)
python -m agents.openhands_llama3.run --task-id CVE-2024-57970_libarchive --level L3 --max-iters 10

# If success reported, note the iteration number (e.g., iter_007)
```

### 3. Manual Verification (RECOMMENDED - Individual Commands)

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

**Why individual commands are better:**
- ✅ Full cleanup between vuln and fixed tests
- ✅ No state accumulation within single evaluate call
- ✅ More reliable crash detection
- ✅ Matches pipeline's double-check behavior

### 4. Alternative: Run Evaluate Command (Less Reliable)

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

### 4. Alternative: Run Evaluate Command (Less Reliable)

```powershell
# Note: evaluate runs both versions in sequence without intermediate cleanup
# Individual commands (section 3) are MORE RELIABLE

# CRITICAL: Clean Docker state before evaluate
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
docker network ls | Select-String "cve-2024"  # Should show NOTHING

# Run evaluate (tests both versions in sequence)
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed "runs\<TIMESTAMP>\CVE-2024-57970_libarchive\iter_XXX\mutated_seed_itXX.bin"
# Expected if valid: vuln_crashes=True fixed_crashes=False success=True

# Clean after evaluate
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
```

**Limitations of evaluate:**
- ❌ Runs both versions without cleanup in between
- ❌ State from vuln test can affect fixed test
- ❌ Less reliable than individual commands
- ⚠️ Only use for quick checks, prefer individual commands for validation

### 5. Verify Consistency (Run Multiple Times with Individual Commands)

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

### 5. Verify Consistency (Run Multiple Times with Individual Commands)

```powershell
# Test 1
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed "runs\<TIMESTAMP>\...\mutated_seed_itXX.bin"
# Note exit_code

docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
python -m scripts.bench run CVE-2024-57970_libarchive --service target-fixed --seed "runs\<TIMESTAMP>\...\mutated_seed_itXX.bin"
# Note exit_code

# Test 2
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed "runs\<TIMESTAMP>\...\mutated_seed_itXX.bin"
# Should get SAME exit_code as Test 1

docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
python -m scripts.bench run CVE-2024-57970_libarchive --service target-fixed --seed "runs\<TIMESTAMP>\...\mutated_seed_itXX.bin"
# Should get SAME exit_code as Test 1

# Test 3
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed "runs\<TIMESTAMP>\...\mutated_seed_itXX.bin"

docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
python -m scripts.bench run CVE-2024-57970_libarchive --service target-fixed --seed "runs\<TIMESTAMP>\...\mutated_seed_itXX.bin"

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

### Test Known Exploit (base_truncated.tar) - Individual Commands
```powershell
# Clean first
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes

# Test vuln
python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed "tasks\CVE-2024-57970_libarchive\seeds\base_truncated.tar"
# Expected: exit_code=139

# Clean
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes

# Test fixed
python -m scripts.bench run CVE-2024-57970_libarchive --service target-fixed --seed "tasks\CVE-2024-57970_libarchive\seeds\base_truncated.tar"
# Expected: exit_code=0

# Clean after
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
```

### Test with Evaluate (Quick Check Only)
```powershell
# Clean first
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes

# Test (less reliable than individual commands)
python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed "tasks\CVE-2024-57970_libarchive\seeds\final_base.tar"
# Expected: vuln_crashes=True fixed_crashes=False success=True

# Clean after
docker compose -f tasks/CVE-2024-57970_libarchive/compose.yml down --volumes
```

## Common Mistakes to AVOID

❌ **Using evaluate instead of individual commands:**
```powershell
# LESS RELIABLE - no cleanup between vuln and fixed tests
python -m scripts.bench evaluate ...
```

✅ **Correct - use individual commands with cleanup:**
```powershell
# MORE RELIABLE - cleanup between each test
docker compose down --volumes
python -m scripts.bench run ... --service target-vuln --seed ...
docker compose down --volumes
python -m scripts.bench run ... --service target-fixed --seed ...
```

❌ **Running tests back-to-back without cleanup:**
```powershell
# WRONG - will give inconsistent results
python -m scripts.bench run ... --service target-vuln ...
python -m scripts.bench run ... --service target-fixed ...  # State from vuln affects this!
```

✅ **Correct - clean between each test:**
```powershell
# RIGHT - consistent results
docker compose down --volumes
python -m scripts.bench run ... --service target-vuln ...
docker compose down --volumes
python -m scripts.bench run ... --service target-fixed ...  # Clean state
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

## Automated Test Script (Individual Commands)

**RECOMMENDED**: Use `test_workflow.py` for complete cleanup + build + verify with infinite retry:
```powershell
python test_workflow.py
```

This script will:
1. Complete Docker cleanup (down + prune)
2. Build from scratch
3. **Verify images with infinite retry** (shows attempt numbers)
4. Validate versions
5. Test with known exploit

Output example:
```
Step 4: Verifying images are ready (infinite retry)
  Checking vulnerable image...
    ○ Attempt 1: (no output, retrying...)
    ○ Attempt 2: (no output, retrying...)
    ○ Attempt 3: (no output, retrying...)
    ✓ Attempt 4: SUCCESS
      ['bsdtar', '3.7.7', '-']
  
  Checking fixed image...
    ○ Attempt 1: (no output, retrying...)
    ✓ Attempt 2: SUCCESS
      ['bsdtar', '3.7.8', '-']
```

---

### Alternative: PowerShell Script for Testing Seeds

Save this as `test_seed.ps1`:

```powershell
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
```

Usage:
```powershell
.\test_seed.ps1 "runs\20260124_XXX\CVE-2024-57970_libarchive\iter_007\mutated_seed_it07.bin"
```

## Why This Workflow is Necessary

1. **Individual commands are more reliable than evaluate**
   - Evaluate runs both versions without intermediate cleanup
   - State from first test can affect second test
   - Individual commands with cleanup = deterministic results

2. **Docker Compose doesn't propagate exit codes** - the fixes in bench.py now handle this, but cleanup is still critical

3. **Networks persist between runs** - the network `cve-2024-57970_libarchive_default` stays alive and affects subsequent tests

4. **Volumes can cache state** - `--volumes` flag removes persistent data

5. **False positives come from stale state** - cleaning between tests prevents this

## Expected Behavior After Fixes

✅ Same seed → Same result (deterministic)
✅ Manual test → Same as subprocess call
✅ Pipeline verify.json → Matches manual validation
✅ No persistent networks between tests
✅ Exit codes correctly propagated from container
✅ Individual commands more reliable than evaluate
✅ Double-check in pipeline uses individual commands with cleanup
