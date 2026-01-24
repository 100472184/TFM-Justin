# DIAGNOSTIC REQUEST: Non-Deterministic Docker/Pipeline Behavior

## SYSTEM OVERVIEW

We have an LLM-guided fuzzing pipeline for CVE exploitation research. The pipeline:
1. Uses Docker Compose to run vulnerable and fixed versions of software
2. Tests mutated seeds to find crashes using differential testing
3. Uses AddressSanitizer (ASan) to detect memory errors

**Key Components:**
- Pipeline: `agents/openhands_llama3/src/pipeline.py` (main orchestration)
- Benchmark runner: `scripts/bench.py` (runs Docker containers)
- Oracle: `scripts/lib/oracle.py` (detects crashes from output)
- Docker setup: `tasks/CVE-2024-57970_libarchive/compose.yml` and `docker/Dockerfile.vuln`

## CRITICAL PROBLEM: Non-Deterministic Crash Detection

### Symptom 1: Same Seed, Different Results

**Known working exploit:** `tasks/CVE-2024-57970_libarchive/seeds/base_truncated.tar` (3072 bytes)

**When run manually in terminal:**
```powershell
PS> python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed "tasks\CVE-2024-57970_libarchive\seeds\base_truncated.tar"

STDERR:
timeout: the monitored command dumped core
/harness/run.sh: line 19:     7 Segmentation fault

exit_code=139  ✓ CRASH DETECTED
```

**When run via subprocess (same command):**
```python
import subprocess, sys
result = subprocess.run(
    [sys.executable, '-m', 'scripts.bench', 'run', 'CVE-2024-57970_libarchive', 
     '--service', 'target-vuln', '--seed', r'tasks\CVE-2024-57970_libarchive\seeds\base_truncated.tar'],
    capture_output=True, text=True, timeout=30
)
# Result: exit_code=0, output="test.txt", NO CRASH
```

**Same seed, same command, different results!**

### Symptom 2: Pipeline False Positives

**Pipeline reported success:**
- File: `runs/20260124_165639_CVE-2024-57970_libarchive/CVE-2024-57970_libarchive/iter_007/verify.json`
- Content shows: `vuln_exit_code: 139, vuln_crashes: true, success: true`
- Seed: `iter_007/mutated_seed_it07.bin` (1022 bytes, truncated)

**Manual validation of same seed:**
```powershell
PS> python -m scripts.bench evaluate CVE-2024-57970_libarchive --seed "runs/.../iter_007/mutated_seed_it07.bin"
# First run: vuln_crashes=True fixed_crashes=False success=True
# Second run: vuln_crashes=False fixed_crashes=True success=False  ← INVERTED!
# Third run: vuln_crashes=False fixed_crashes=False success=False
```

**Running same evaluation multiple times gives DIFFERENT results each time!**

### Symptom 3: Docker Network Persistence

**After any Docker run:**
```powershell
PS> docker network ls | Select-String "cve-2024"
4882191bde76   cve-2024-57970_libarchive_default   bridge    local
```

Network persists even after:
- `docker compose down --volumes`
- Pipeline cleanup function running
- `cleanup_docker()` completing successfully

**Hypothesis:** This persistent network state causes different behavior between runs.

## FILES TO EXAMINE

### 1. Pipeline Verification Function
**File:** `agents/openhands_llama3/src/pipeline.py`
**Lines:** 17-70 (function `run_benchmark_subprocess`)

Current implementation:
```python
def run_benchmark_subprocess(repo_root: Path, task_id: str, service: str, seed_path: Path) -> tuple[int, bool]:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "scripts.bench", "run", task_id, "--service", service, "--seed", str(seed_path)],
            capture_output=True, text=True, timeout=30, cwd=str(repo_root)
        )
        
        crash_keywords = re.compile(
            r"segmentation fault|dumped core|core dumped|SIGSEGV|SIGABRT|"
            r"heap-buffer-overflow|stack-buffer-overflow|use-after-free|double-free|"
            r"AddressSanitizer|UndefinedBehaviorSanitizer", re.IGNORECASE
        )
        
        combined = result.stdout + result.stderr
        crashes = bool(crash_keywords.search(combined) or result.returncode in [139, 134, -11, -6])
        
        return result.returncode, crashes
    except Exception as e:
        return -2, False
```

**Questions:**
- Why does subprocess get exit_code=0 when terminal shows exit_code=139?
- Does Docker Compose swallow the container's exit code?
- Should we parse the output text "exit_code=139" instead of using `result.returncode`?

### 2. Benchmark Runner
**File:** `scripts/bench.py`
**Lines:** 35-43 (function `_run_service`)

```python
def _run_service(tdir: Path, service: str, seed: Path) -> RunResult:
    out = docker_compose(
        tdir,
        [
            "run", "--rm",
            "-v", f"{seed.resolve()}:/input/seed.bin:ro",
            service
        ],
    )
    return RunResult(exit_code=out.exit_code, stdout=out.stdout, stderr=out.stderr)
```

**Questions:**
- What does `docker_compose()` return in `out.exit_code`?
- Does it capture the container's actual exit code or Docker Compose's exit code?
- Check `scripts/lib/docker.py` - does it properly propagate exit codes?

### 3. Docker Compose Helper
**File:** `scripts/lib/docker.py`
**Check:** How does `docker_compose()` function work?

### 4. Cleanup Function
**File:** `agents/openhands_llama3/src/pipeline.py`
**Lines:** 75-140 (function `cleanup_docker`)

Current 3-step cleanup:
```python
# Step 1: docker compose down --volumes --remove-orphans
# Step 2: Force remove containers by name filter
# Step 3: Force remove network by name (f"{task_id.replace('_', '-')}_default")
```

**Questions:**
- Is Step 3 actually executing? (Should add logging)
- Does network removal fail silently in the `except: pass` block?
- Should cleanup run BEFORE verification, not just before/after iteration?

### 5. Docker Harness Script
**File:** `tasks/CVE-2024-57970_libarchive/harness/run.sh`

Check what this script does and how it reports exit codes.

### 6. Example Run Directories
**Compare these two runs:**

1. **Pipeline run with false positive:**
   - `runs/20260124_165639_CVE-2024-57970_libarchive/CVE-2024-57970_libarchive/iter_007/`
   - Check: `verify.json`, `mutated_seed_it07.bin`

2. **Recent run with exit_code=-2 errors:**
   - `runs/20260124_191407_CVE-2024-57970_libarchive/CVE-2024-57970_libarchive/iter_001/`
   - Check: `verify.json`, `mutated_seed_it01.bin`

## SPECIFIC QUESTIONS TO ANSWER

1. **Exit Code Propagation:**
   - Does `docker compose run` return the container's exit code or always return 0?
   - Should we parse the text "exit_code=139" from stdout instead?
   - Check if harness script uses `exit $?` to propagate exit codes

2. **Docker Network State:**
   - Why does the network persist after `docker compose down --volumes`?
   - Does network state affect container behavior (caching, volumes, etc.)?
   - Should we remove network BEFORE each run, not just after?

3. **Non-Determinism Root Cause:**
   - Is this a Docker caching issue?
   - Is this a race condition in container cleanup?
   - Is this ASan non-determinism (heap layout randomization)?
   - Is this related to Docker build cache corrupting images?

4. **Verification Logic:**
   - Should we call `docker compose down` explicitly before each benchmark run?
   - Should we verify by running the command TWICE and comparing results?
   - Should we add retries with cleanup between attempts?

## REPRODUCTION STEPS

1. **Setup:**
   ```powershell
   cd D:\JustainoTitaino\TFM-Justin
   python -m scripts.bench build CVE-2024-57970_libarchive
   ```

2. **Test known exploit manually:**
   ```powershell
   python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed "tasks\CVE-2024-57970_libarchive\seeds\base_truncated.tar"
   # Note the exit code
   ```

3. **Test same exploit via Python subprocess:**
   ```powershell
   python test_detection.py
   # Compare exit code with manual run
   ```

4. **Check Docker network state:**
   ```powershell
   docker network ls | Select-String "cve-2024"
   # Network should NOT exist but does
   ```

5. **Remove network and retry:**
   ```powershell
   docker network rm cve-2024-57970_libarchive_default
   python test_detection.py
   # Check if behavior changes
   ```

## EXPECTED BEHAVIOR

**Consistent results:** Same seed should ALWAYS give same crash detection result, regardless of:
- Running in terminal vs subprocess
- Running first time vs subsequent times
- Network state (should be cleaned between runs)

**Current behavior:** Results vary randomly, making the oracle unreliable.

## WHAT WE NEED

1. **Root cause identification:** Why does subprocess get different exit codes than manual runs?
2. **Reliable fix:** How to ensure Docker state is completely clean between tests?
3. **Verification:** How to validate that fix actually works (reproducible results)?

## ADDITIONAL CONTEXT

- Environment: Windows 11, PowerShell, Docker Desktop, Python 3.11
- Docker Compose V2 (docker compose, not docker-compose)
- ASan compiled into binaries (confirmed with `strings` check)
- Known working: base_truncated.tar DOES crash vuln version when Docker state is clean
- Issue appeared after: Multiple test runs accumulating Docker state

Please analyze the files mentioned above and provide:
1. Diagnosis of why exit codes differ between terminal and subprocess
2. Explanation of Docker network persistence and its impact
3. Recommended fixes with specific code changes
4. Testing procedure to validate the fixes work
