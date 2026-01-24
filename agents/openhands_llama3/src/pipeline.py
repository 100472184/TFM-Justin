"""Main pipeline orchestration for ANALYZE → GENERATE → VERIFY loop."""
from __future__ import annotations
import json
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
    Clean Docker containers and volumes to prevent stale state between iterations.
    
    This is critical because Docker containers can cache state that causes
    inconsistent results between pipeline runs and manual verification.
    """
    compose_file = repo_root / "tasks" / task_id / "compose.yml"
    
    if not compose_file.exists():
        print(f"  [yellow]Warning: compose.yml not found at {compose_file}[/yellow]")
        return
    
    try:
        # Step 1: Stop and remove containers with volumes
        cmd = [
            "docker", "compose",
            "-f", str(compose_file),
            "down", "--volumes", "--remove-orphans"
        ]
        
        result = subprocess.run(
            cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"  [yellow]Warning: Docker cleanup failed: {result.stderr}[/yellow]")
            return
        
        # Step 2: Force remove any lingering containers
        try:
            result = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"name={task_id}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            container_ids = result.stdout.strip().split('\n')
            if container_ids and container_ids[0]:
                for cid in container_ids:
                    subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=5)
        except Exception:
            pass  # Best effort
        
        # Step 3: Force remove the network
        try:
            network_name = f"{task_id.replace('_', '-')}_default"
            subprocess.run(
                ["docker", "network", "rm", network_name],
                capture_output=True,
                text=True,
                timeout=10
            )
        except Exception:
            pass  # Best effort - network may not exist
    
    except subprocess.TimeoutExpired:
        print(f"  [yellow]Warning: Docker cleanup timed out[/yellow]")
    except Exception as e:
        print(f"  [yellow]Warning: Docker cleanup error: {e}[/yellow]")


def run_benchmark(
    repo_root: Path,
    task_id: str,
    service: str,
    seed_path: Path
) -> Dict:
    """
    Execute benchmark command and capture results.
    
    Returns dict with:
    - exit_code: int
    - stdout: str
    - stderr: str
    - success_signal: bool
    """
    # Build command: python -m scripts.bench run <task_id> --service <service> --seed <seed_path>
    # Use sys.executable to ensure same Python interpreter (with venv dependencies)
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
            timeout=180  # 3 minute timeout
        )
        
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
        
        # CRITICAL: Parse the real exit code from stdout
        # bench.py prints "exit_code=NNN" at the end
        import re
        match = re.search(r'exit_code=(\d+)', stdout)
        if match:
            real_exit_code = int(match.group(1))
            # Use the real exit code from the binary, not the bench.py wrapper
            exit_code = real_exit_code
    
    except subprocess.TimeoutExpired:
        stdout = ""
        stderr = "TIMEOUT: Command exceeded 180 seconds"
        exit_code = -1
    
    except Exception as e:
        stdout = ""
        stderr = f"ERROR: {str(e)}"
        exit_code = -2
    
    success_signal = detect_success_signal(stdout, stderr, exit_code)
    
    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "success_signal": success_signal,
        "notes": "Vulnerability triggered" if success_signal else "No crash detected"
    }


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
    print(f"[bold cyan]Loading context for {task_id} at level {level}...[/bold cyan]")
    context = load_task_context(repo_root, task_id, level)
    
    # Initialize LLM client
    print("[bold cyan]Initializing LLM client...[/bold cyan]")
    llm = OpenHandsLLMClient()
    
    # Convert seed_path to Path if it's a string, or set to None if not provided
    if seed_path is None:
        # No seed provided, try to find base.tar
        task_seeds_dir = repo_root / "tasks" / task_id / "seeds"
        base_seed = task_seeds_dir / "base.tar"
        
        if base_seed.exists():
            print(f"[bold green]✓ Using base seed: {base_seed}[/bold green]")
            current_seed = read_bytes(base_seed)
        else:
            print(f"[yellow]Warning: No seed or base.tar found, creating minimal seed[/yellow]")
            current_seed = b"\x00" * 512  # Minimal TAR block
    elif isinstance(seed_path, str):
        seed_path = Path(seed_path)
        if seed_path.exists():
            print(f"[bold green]✓ Loading seed from: {seed_path}[/bold green]")
            current_seed = read_bytes(seed_path)
        else:
            print(f"[bold red]✗ Seed not found: {seed_path}[/bold red]")
            raise FileNotFoundError(f"Seed file not found: {seed_path}")
    else:
        # seed_path is already a Path object
        if seed_path.exists():
            print(f"[bold green]✓ Loading seed from: {seed_path}[/bold green]")
            current_seed = read_bytes(seed_path)
        else:
            print(f"[bold red]✗ Seed not found: {seed_path}[/bold red]")
            raise FileNotFoundError(f"Seed file not found: {seed_path}")
    
    # Setup Jinja2 templates
    templates_dir = Path(__file__).parent.parent / "prompt_templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)))
    
    # History for prompts
    verify_history = []
    
    success = False
    
    for iteration in range(1, max_iters + 1):
        print(f"\n[bold magenta]{'='*60}[/bold magenta]")
        print(f"[bold magenta]ITERATION {iteration}/{max_iters}[/bold magenta]")
        print(f"[bold magenta]{'='*60}[/bold magenta]")
        
        iter_dir = run_dir / f"iter_{iteration:03d}"
        ensure_dir(iter_dir)
        
        # Clean Docker state BEFORE starting iteration to prevent corruption
        print("\n  Cleaning Docker state before iteration...")
        cleanup_docker(repo_root, task_id)
        
        # ===== PHASE 1: ANALYZE =====
        print("\n[bold green]→ ANALYZE[/bold green]")
        
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
        print("\n[bold green]→ GENERATE[/bold green]")
        
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
        print("\n[bold green]→ VERIFY[/bold green]")
        
        # Test BOTH vulnerable and fixed versions to ensure CVE-specific crash
        print("  Testing vulnerable version...")
        verify_vuln = run_benchmark(repo_root, task_id, service, seed_file)
        
        print("  Testing fixed version...")
        verify_fixed = run_benchmark(repo_root, task_id, "target-fixed", seed_file)
        
        # Combine results
        verify_result = {
            "vuln_exit_code": verify_vuln["exit_code"],
            "vuln_stdout": verify_vuln["stdout"],
            "vuln_stderr": verify_vuln["stderr"],
            "vuln_crashes": verify_vuln["success_signal"],
            "fixed_exit_code": verify_fixed["exit_code"],
            "fixed_stdout": verify_fixed["stdout"],
            "fixed_stderr": verify_fixed["stderr"],
            "fixed_crashes": verify_fixed["success_signal"],
            "success": verify_vuln["success_signal"] and not verify_fixed["success_signal"],
            "notes": "CVE-specific crash" if (verify_vuln["success_signal"] and not verify_fixed["success_signal"]) else 
                     "Both versions crash" if (verify_vuln["success_signal"] and verify_fixed["success_signal"]) else
                     "No crash detected",
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
        print(f"  [bold]Success: {verify_result['success']}[/bold] - {verify_result['notes']}")
        
        # Clean Docker containers after verification (redundant with pre-iteration cleanup, but safe)
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
            print(f"\n[bold green]🎉 SUCCESS! CVE-specific crash detected in iteration {iteration}[/bold green]")
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
    
    print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    print(f"[bold cyan]Run complete: {run_dir}[/bold cyan]")
    print(f"[bold cyan]Success: {success}[/bold cyan]")
    print(f"[bold cyan]{'='*60}[/bold cyan]")
    
    return {
        "success": success,
        "iteration": iteration,
        "run_dir": str(run_dir)
    }
