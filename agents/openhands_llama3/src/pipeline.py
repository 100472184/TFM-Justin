"""Main pipeline orchestration for ANALYZE → GENERATE → VERIFY loop."""
from __future__ import annotations
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader

from .io_utils import (
    read_bytes, write_bytes, write_text, ensure_dir,
    now_run_id, safe_truncate
)
from .context_builder import load_task_context
from .mutations import apply_mutations
from .openhands_client import OpenHandsLLMClient


def detect_success_signal(stdout: str, stderr: str, exit_code: int) -> bool:
    """
    Detect if execution shows crash/sanitizer signals.
    
    Success indicators:
    - Crash exit codes (139=SIGSEGV, 134=SIGABRT)
    - Sanitizer keywords in stderr/stdout
    - Core dumps, segmentation faults
    """
    # Keywords that indicate success (vulnerability triggered)
    CRASH_KEYWORDS = [
        "addresssanitizer",           # ASan
        "undefinedbehaviorsanitizer", # UBSan
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "heap-use-after-free",
        "segv",
        "sigsegv",
        "sigabrt",
        "double-free",
        "use-after-free",
        "out-of-bounds",
        "asan:",
        "ubsan:",
        "segmentation fault",
        "dumped core",
        "core dumped",
        "aborted",
        "summary: addresssanitizer",  # ASan summary
        "summary: undefinedbehavior", # UBSan summary
    ]
    
    combined_output = (stdout + "\n" + stderr).lower()
    
    # Check for keywords (all lowercase now)
    for keyword in CRASH_KEYWORDS:
        if keyword in combined_output:
            print(f"[cyan]  ✓ Detected crash keyword: '{keyword}'[/cyan]")
            return True
    
    # Check exit codes that indicate crash
    # 139 = 128 + 11 (SIGSEGV)
    # 134 = 128 + 6 (SIGABRT)
    CRASH_EXIT_CODES = [139, 134, -11, -6, 11, 6]
    if exit_code in CRASH_EXIT_CODES:
        print(f"[cyan]  ✓ Detected crash exit code: {exit_code}[/cyan]")
        return True
    # 134 = 128 + 6 (SIGABRT)
    if exit_code in [139, 134, -11, -6]:
        return True
    
    # Non-zero exit code might indicate crash
    # But be conservative: only consider it success if keywords found
    return False


def cleanup_docker(repo_root: Path, task_id: str) -> None:
    """
    Clean Docker containers, volumes and networks to prevent stale state.
    
    All cleanup steps run regardless of earlier failures to ensure maximum cleanup.
    """
    compose_file = repo_root / "tasks" / task_id / "compose.yml"
    
    if not compose_file.exists():
        print(f"  [yellow]Warning: compose.yml not found at {compose_file}[/yellow]")
        return
    
    # Step 1: Bring down services and remove volumes/orphans
    # Always attempt this, even if it returns non-zero (common on Windows when nothing is running)
    try:
        cmd = ["docker", "compose", "-f", str(compose_file), 
               "down", "--volumes", "--remove-orphans"]
        result = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode != 0:
            print(f"  [yellow]Warning: docker compose down returned {result.returncode}: {result.stderr.strip()}[/yellow]")
    except Exception as e:
        print(f"  [yellow]Warning: docker compose down error: {e}[/yellow]")
    
    # Step 2: Force remove any lingering containers whose name contains the task_id
    try:
        ps = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"name={task_id}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        for cid in filter(None, ps.stdout.strip().split("\n")):
            subprocess.run(["docker", "rm", "-f", cid], 
                         capture_output=True, timeout=5)
    except Exception as e:
        print(f"  [yellow]Warning: failed to remove containers: {e}[/yellow]")
    
    # Step 3: Remove the Compose network (always lowercase with underscores)
    # Compose creates networks as <task_id.lower()>_default
    try:
        network_name = f"{task_id.lower()}_default"
        result = subprocess.run(
            ["docker", "network", "rm", network_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0 and "not found" not in result.stderr.lower():
            print(f"  [yellow]Warning: failed to remove network {network_name}: {result.stderr.strip()}[/yellow]")
    except Exception as e:
        print(f"  [yellow]Warning: network removal error: {e}[/yellow]")


def run_benchmark(
    repo_root: Path,
    task_id: str,
    service: str,
    seed_path: Path
) -> Dict:
    """
    Execute benchmark via subprocess - matches manual testing that works reliably.
    
    Returns dict with:
    - exit_code: int (actual binary exit code)
    - stdout: str
    - stderr: str
    - crashes: bool (True if crash detected)
    """
    cmd = [
        sys.executable, "-m", "scripts.bench",
        "run", task_id,
        "--service", service,
        "--seed", str(seed_path.absolute())
    ]
    
    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=180,
            shell=False
        )
        
        # Check if bench.py command itself failed
        if result.returncode != 0 and "exit_code=" not in result.stdout:
            # This means bench.py itself failed, not the target binary
            print(f"  WARNING: bench.py failed with return code {result.returncode}")
            print(f"  STDERR: {result.stderr[:200]}")
        
        full_output = result.stdout + "\n" + result.stderr
        
        # Extract actual exit code from bench.py output
        exit_code = 0
        match = re.search(r'exit_code=(\d+)', full_output)
        if match:
            exit_code = int(match.group(1))
        
        # Detect crashes using multiple signals
        crashes = False
        
        # Signal 1: Crash exit codes
        if exit_code in [139, 134, 11, 6, -11, -6]:
            crashes = True
            print(f"  ✓ Detected crash via exit code: {exit_code}")
        
        # Signal 2: Sanitizer reports
        if re.search(r'AddressSanitizer|UndefinedBehaviorSanitizer|SUMMARY: .*Sanitizer', full_output, re.IGNORECASE):
            crashes = True
            print(f"  ✓ Detected sanitizer report")
        
        # Signal 3: Crash keywords
        crash_keywords = [
            'segmentation fault', 'dumped core', 'core dumped',
            'SIGSEGV', 'SIGABRT', 'heap-buffer-overflow',
            'stack-buffer-overflow', 'use-after-free', 'double-free'
        ]
        for keyword in crash_keywords:
            if keyword.lower() in full_output.lower():
                crashes = True
                print(f"  ✓ Detected crash keyword: '{keyword}'")
                break
        
        return {
            "exit_code": exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "crashes": crashes
        }
    
    except subprocess.TimeoutExpired:
        print(f"  ERROR: Timeout after 180s")
        return {"exit_code": -1, "stdout": "", "stderr": "TIMEOUT", "crashes": False}
    except Exception as e:
        print(f"  ERROR: Exception during benchmark: {e}")
        print(f"  Command was: {' '.join(cmd)}")
        return {"exit_code": -2, "stdout": "", "stderr": f"ERROR: {e}", "crashes": False}


def run_pipeline(
    repo_root: Path,
    task_id: str,
    level: str,
    max_iters: int,
    seed_path: Path,
    service: str = "target-vuln",
    extra_args: List[str] = None
) -> Dict[str, Any]:
    """
    Run the complete ANALYZE → GENERATE → VERIFY pipeline.
    
    Returns:
        Dict with keys: success (bool), iteration (int), run_dir (Path)
    """
    extra_args = extra_args or []
    
    # Create run directory
    run_id = now_run_id()
    task_run_dir = f"{run_id}_{task_id}"
    run_dir = repo_root / "runs" / task_run_dir / task_id
    ensure_dir(run_dir)
    
    # Load context
    print(f"Loading context for {task_id} at level {level}...")
    context = load_task_context(repo_root, task_id, level)
    
    # Initialize LLM client
    print("Initializing LLM client...")
    llm = OpenHandsLLMClient()
    
    # Convert seed_path to Path if it's a string, or set to None if not provided
    if seed_path is None:
        # No seed provided, try to find base.tar
        task_seeds_dir = repo_root / "tasks" / task_id / "seeds"
        base_seed = task_seeds_dir / "base.tar"
        
        if base_seed.exists():
            print(f"✓ Using base seed: {base_seed}")
            current_seed = read_bytes(base_seed)
        else:
            print(f"[yellow]Warning: No seed or base.tar found, creating minimal seed[/yellow]")
            current_seed = b"\x00" * 512  # Minimal TAR block
    elif isinstance(seed_path, str):
        seed_path = Path(seed_path)
        if seed_path.exists():
            print(f"✓ Loading seed from: {seed_path}")
            current_seed = read_bytes(seed_path)
        else:
            print(f"✗ Seed not found: {seed_path}")
            raise FileNotFoundError(f"Seed file not found: {seed_path}")
    else:
        # seed_path is already a Path object
        if seed_path.exists():
            print(f"✓ Loading seed from: {seed_path}")
            current_seed = read_bytes(seed_path)
        else:
            print(f"✗ Seed not found: {seed_path}")
            raise FileNotFoundError(f"Seed file not found: {seed_path}")
    
    # Setup Jinja2 templates
    templates_dir = Path(__file__).parent.parent / "prompt_templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)))
    
    # History for prompts
    verify_history = []
    
    success = False
    
    for iteration in range(1, max_iters + 1):
        print(f"\n{'='*60}")
        print(f"ITERATION {iteration}/{max_iters}")
        print(f"{'='*60}")
        
        iter_dir = run_dir / f"iter_{iteration:03d}"
        ensure_dir(iter_dir)
        
        # Clean Docker state BEFORE starting iteration to prevent corruption
        print("\n  Cleaning Docker state before iteration...")
        cleanup_docker(repo_root, task_id)
        
        # ===== PHASE 1: ANALYZE =====
        print("\n→ ANALYZE")
        
        analyze_template = env.get_template("analyze.j2")
        analyze_prompt = analyze_template.render(
            task_id=task_id,
            level=level,
            context=context,
            iteration=iteration,
            max_iters=max_iters,
            verify_history=verify_history[-3:]  # Last 3 results
        )
        
        analysis = llm.completion_json(
            schema_name="analyze",
            system_prompt="You are a security researcher analyzing CVE vulnerabilities for academic research.",
            user_prompt=analyze_prompt
        )
        
        write_text(iter_dir / "analysis.json", json.dumps(analysis, indent=2))
        print(f"  Summary: {analysis.get('summary', 'N/A')[:100]}...")
        
        # Check for early stop
        if analysis.get("stop_early", False):
            print("[yellow]  LLM requested early stop[/yellow]")
            break
        
        # ===== PHASE 2: GENERATE =====
        print("\n→ GENERATE")
        
        # Prepare seed preview (hex, truncated)
        seed_hex = current_seed.hex()
        if len(seed_hex) > 1024:
            seed_preview = seed_hex[:1024] + f"... ({len(current_seed)} bytes total)"
        else:
            seed_preview = seed_hex
        
        generate_template = env.get_template("generate.j2")
        generate_prompt = generate_template.render(
            task_id=task_id,
            analysis=analysis,
            seed_preview=seed_preview,
            seed_length=len(current_seed),
            iteration=iteration,
            verify_history=verify_history[-3:]
        )
        
        generation = llm.completion_json(
            schema_name="generate",
            system_prompt="You are a security researcher proposing seed mutations for vulnerability research.",
            user_prompt=generate_prompt
        )
        
        write_text(iter_dir / "generate.json", json.dumps(generation, indent=2))
        print(f"  Rationale: {generation.get('rationale', 'N/A')[:100]}...")
        
        # Apply mutations
        mutations = generation.get("mutations", [])
        mutation_success = False
        mutation_error = None
        
        if not mutations:
            print("[yellow]  No mutations proposed, skipping VERIFY[/yellow]")
            new_seed = current_seed
            mutation_error = "No mutations proposed by LLM"
            # Skip VERIFY phase when no mutations
            continue
        else:
            try:
                new_seed = apply_mutations(current_seed, mutations)
                print(f"  Applied {len(mutations)} mutation(s): {len(current_seed)} → {len(new_seed)} bytes")
                mutation_success = True
            except Exception as e:
                print(f"[red]  Mutation failed: {e}[/red]")
                print(f"[yellow]  Skipping VERIFY for this iteration[/yellow]")
                mutation_error = str(e)
                
                # Save failed state to JSON for feedback
                verify_result = {
                    "vuln_exit_code": None,
                    "vuln_stdout": "",
                    "vuln_stderr": "",
                    "vuln_crashes": False,
                    "fixed_exit_code": None,
                    "fixed_stdout": "",
                    "fixed_stderr": "",
                    "fixed_crashes": False,
                    "success": False,
                    "notes": f"Mutation failed: {mutation_error}",
                    "mutation_applied": False,
                    "mutation_error": mutation_error
                }
                
                write_text(iter_dir / "verify.json", json.dumps(verify_result, indent=2))
                
                # Add to history so LLM learns from mistake
                verify_history.append({
                    "iteration": iteration,
                    "vuln_crashes": False,
                    "fixed_crashes": False,
                    "vuln_exit_code": None,
                    "fixed_exit_code": None,
                    "success": False,
                    "notes": f"Mutation failed: {mutation_error}",
                    "mutations_applied": mutations,
                    "mutation_success": False,
                    "mutation_error": mutation_error,
                    "vuln_stderr_preview": "",
                    "fixed_stderr_preview": ""
                })
                
                # Skip VERIFY phase and continue to next iteration
                continue
        
        # Save new seed only if mutation succeeded
        seed_filename = f"mutated_seed_it{iteration:02d}.bin"
        seed_file = iter_dir / seed_filename
        write_bytes(seed_file, new_seed)
        current_seed = new_seed
        
        # ===== PHASE 3: VERIFY =====
        print("\n→ VERIFY")
        
        # Clean before testing vulnerable version
        print("  Cleaning Docker state before vuln test...")
        cleanup_docker(repo_root, task_id)
        
        print("  Testing vulnerable version...")
        verify_vuln = run_benchmark(repo_root, task_id, service, seed_file)
        
        # Clean before testing fixed version
        print("  Cleaning Docker state before fixed test...")
        cleanup_docker(repo_root, task_id)
        
        print("  Testing fixed version...")
        verify_fixed = run_benchmark(repo_root, task_id, "target-fixed", seed_file)
        
        # Use 'crashes' field from run_benchmark
        vuln_crashes = verify_vuln["crashes"]
        fixed_crashes = verify_fixed["crashes"]
        success = vuln_crashes and not fixed_crashes
        
        if success:
            notes = "CVE-specific crash"
        elif vuln_crashes and fixed_crashes:
            notes = "Both versions crash"
        elif not vuln_crashes and fixed_crashes:
            notes = "Only fixed crashes (inverted)"
        else:
            notes = "No crash detected"
        
        verify_result = {
            "vuln_exit_code": verify_vuln["exit_code"],
            "vuln_stdout": verify_vuln["stdout"],
            "vuln_stderr": verify_vuln["stderr"],
            "vuln_crashes": vuln_crashes,
            "fixed_exit_code": verify_fixed["exit_code"],
            "fixed_stdout": verify_fixed["stdout"],
            "fixed_stderr": verify_fixed["stderr"],
            "fixed_crashes": fixed_crashes,
            "success": success,
            "notes": notes,
            "mutation_applied": mutation_success,
            "mutation_error": mutation_error
        }
        
        write_text(iter_dir / "verify.json", json.dumps(verify_result, indent=2))
        
        # Save command
        cmd_vuln = f"python -m scripts.bench run {task_id} --service target-vuln --seed {seed_file}"
        cmd_fixed = f"python -m scripts.bench run {task_id} --service target-fixed --seed {seed_file}"
        cmd_eval = f"python -m scripts.bench evaluate {task_id} --seed {seed_file}"
        write_text(iter_dir / "command.txt", f"{cmd_vuln}\n\n# Fixed version:\n{cmd_fixed}\n\n# Evaluate:\n{cmd_eval}")
        
        print(f"  Vulnerable: exit_code={verify_result['vuln_exit_code']}, crashes={verify_result['vuln_crashes']}")
        print(f"  Fixed: exit_code={verify_result['fixed_exit_code']}, crashes={verify_result['fixed_crashes']}")
        print(f"  Success: {verify_result['success']} - {verify_result['notes']}")
        
        # DOUBLE-CHECK: Validate any success claim with individual commands
        if verify_result['success']:
            print("\n  ⚠️  SUCCESS DETECTED - Running validation check with individual commands...")
            
            # Clean Docker state before first validation run
            print("  Cleaning Docker state before vuln recheck...")
            cleanup_docker(repo_root, task_id)
            
            # Recheck vulnerable version
            print("  Validating vulnerable version crashes...")
            recheck_vuln = run_benchmark(repo_root, task_id, service, seed_file)
            
            # Clean Docker state before fixed version
            print("  Cleaning Docker state before fixed recheck...")
            cleanup_docker(repo_root, task_id)
            
            # Recheck fixed version
            print("  Validating fixed version doesn't crash...")
            recheck_fixed = run_benchmark(repo_root, task_id, "target-fixed", seed_file)
            
            if recheck_vuln["crashes"] and not recheck_fixed["crashes"]:
                print("  ✓ VALIDATION PASSED - Crash is reproducible")
            else:
                print(f"  ✗ VALIDATION FAILED - Marking as FALSE POSITIVE")
                print(f"    Original: vuln={vuln_crashes}, fixed={fixed_crashes}")
                print(f"    Recheck: vuln={recheck_vuln['crashes']}, fixed={recheck_fixed['crashes']}")
                verify_result['success'] = False
                verify_result['notes'] = "False positive - not reproducible"
                write_text(iter_dir / "verify.json", json.dumps(verify_result, indent=2))
        
        print("  Cleaning Docker containers...")
        cleanup_docker(repo_root, task_id)
        
        # Add to history with complete information for next iteration
        verify_history.append({
            "iteration": iteration,
            "vuln_crashes": verify_result["vuln_crashes"],
            "fixed_crashes": verify_result["fixed_crashes"],
            "vuln_exit_code": verify_result["vuln_exit_code"],
            "fixed_exit_code": verify_result["fixed_exit_code"],
            "success": verify_result["success"],
            "notes": verify_result["notes"],
            "mutations_applied": mutations if mutations else [],
            "mutation_success": mutation_success,
            "mutation_error": mutation_error,
            "vuln_stderr_preview": safe_truncate(verify_result["vuln_stdout"], 500),
            "fixed_stderr_preview": safe_truncate(verify_result["fixed_stdout"], 500)
        })
        
        # Check success - now based on CVE-specific crash
        if verify_result["success"]:
            print(f"\n🎉 SUCCESS! CVE-specific crash detected in iteration {iteration}")
            success = True
            break
    
    # ===== SUMMARY =====
    summary = {
        "task_id": task_id,
        "level": level,
        "max_iters": max_iters,
        "total_iters": len(verify_history),
        "success": success,
        "success_iter": iteration if success else None,
        "run_dir": str(run_dir),
        "timestamp": run_id
    }
    
    write_text(run_dir / "summary.json", json.dumps(summary, indent=2))
    
    print(f"\n{'='*60}")
    print(f"Run complete: {run_dir}")
    print(f"Success: {success}")
    print(f"{'='*60}")
    
    return {
        "success": success,
        "iteration": iteration,
        "run_dir": str(run_dir)
    }
