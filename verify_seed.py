#!/usr/bin/env python3
"""
Verify a generated seed with complete Docker workflow.

This script implements the same sequence as test_workflow.py but tests
a specific seed file (e.g., from pipeline output) instead of final_base.tar.

Usage:
    python verify_seed.py <seed_path>
    python verify_seed.py runs\20260125_XXX\CVE-2024-57970_libarchive\iter_003\mutated_seed_it03.bin
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Add repo root to path
repo_root = Path(__file__).parent
sys.path.insert(0, str(repo_root))


TASK_ID = "CVE-2024-57970_libarchive"
COMPOSE_FILE = f"tasks/{TASK_ID}/compose.yml"


def run_command(cmd: list[str], description: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and print its description."""
    print(f"\n{'='*60}")
    print(f"  {description}")
    print(f"{'='*60}")
    print(f"$ {' '.join(cmd)}\n")
    
    result = subprocess.run(cmd, check=False, text=True, capture_output=True)
    
    # Print stdout if present
    if result.stdout:
        print(result.stdout)
    
    if check and result.returncode != 0:
        print(f"\n[ERROR] Command failed with exit code {result.returncode}")
        if result.stderr:
            print(f"stderr: {result.stderr}")
        sys.exit(1)
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Verify a seed with complete Docker cleanup workflow"
    )
    parser.add_argument(
        "seed_path",
        help="Path to the seed file to test (e.g., runs/.../mutated_seed_it03.bin)"
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Save results to runs/verifications/ directory as JSON"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="Custom output directory for results (default: runs/verifications/)"
    )
    args = parser.parse_args()
    
    seed_path = Path(args.seed_path)
    if not seed_path.exists():
        print(f"\n[ERROR] Seed file not found: {seed_path}")
        sys.exit(1)
    
    print(f"""
{'='*60}
CVE-2024-57970 Seed Verification Workflow
{'='*60}

Seed to verify: {seed_path.name}
Full path: {seed_path}

This script will:
1. Destroy all Docker images and volumes
2. Clean Docker system cache
3. Rebuild images from scratch
4. Verify images are ready (with automatic retry)
5. Validate versions (vuln=3.7.7, fixed=3.7.8)
6. Test with your seed file

Press Ctrl+C now to cancel, or Enter to continue...
""")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\n\nCancelled by user")
        sys.exit(0)
    
    # Step 1: Complete Docker cleanup
    run_command(
        ["docker", "compose", "-f", COMPOSE_FILE, "down", "--volumes", "--rmi", "all"],
        "Step 1: Destroying Docker images and volumes"
    )
    
    # Step 2: System-wide prune
    run_command(
        ["docker", "system", "prune", "-af", "--volumes"],
        "Step 2: Cleaning Docker system cache"
    )
    
    # Step 3: Rebuild images
    run_command(
        [sys.executable, "-m", "scripts.bench", "build", TASK_ID],
        "Step 3: Building Docker images from scratch"
    )
    
    # Step 4: Verify images are ready - EXACT logic from test_docker_ready.py
    print(f"\n{'='*60}")
    print(f"  Step 4: Verifying images are ready")
    print(f"{'='*60}\n")
    
    print("  Using validated timing: NO timeout, 2s wait between attempts")
    print("  Expected: 1-3 attempts per image (~0.8-1s per attempt)\n")
    
    # Verify vulnerable image - EXACT logic from test_docker_ready.py
    # Docker image names must be lowercase
    vuln_image = f"{TASK_ID.lower()}-target-vuln"
    vuln_cmd = ["docker", "run", "--rm", "--entrypoint", "/opt/target/bin/bsdtar", vuln_image, "--version"]
    
    print(f"  Vulnerable image: {vuln_image}")
    print(f"  Command: {' '.join(vuln_cmd)}\n")
    
    attempt = 1
    vuln_version = None
    while vuln_version is None:
        print(f"    [{time.strftime('%H:%M:%S')}] Attempt {attempt}: Starting command...")
        start_time = time.time()
        
        try:
            # NO TIMEOUT - let the command finish naturally
            # This is CRITICAL - must match test_docker_ready.py exactly
            result = subprocess.run(
                vuln_cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            elapsed = time.time() - start_time
            
            # Check if we got output
            if result.stdout.strip():
                vuln_version = result.stdout.strip()
                print(f"    [{time.strftime('%H:%M:%S')}] Attempt {attempt}: ✓ SUCCESS after {elapsed:.2f}s")
                print(f"    Output: {vuln_version}")
                break
            else:
                print(f"    [{time.strftime('%H:%M:%S')}] Attempt {attempt}: ○ No output after {elapsed:.2f}s")
                
                # Show stderr if present
                if result.stderr.strip():
                    print(f"      stderr: {result.stderr.strip()[:100]}")
                
                # Wait before next attempt
                print(f"    [{time.strftime('%H:%M:%S')}]   Waiting 2 seconds before next attempt...")
                time.sleep(2.0)
                attempt += 1
                
        except KeyboardInterrupt:
            print("\n\nCancelled by user")
            sys.exit(1)
    
    # Verify fixed image - EXACT logic from test_docker_ready.py
    # Docker image names must be lowercase
    fixed_image = f"{TASK_ID.lower()}-target-fixed"
    fixed_cmd = ["docker", "run", "--rm", "--entrypoint", "/opt/target/bin/bsdtar", fixed_image, "--version"]
    
    print(f"\n  Fixed image: {fixed_image}")
    print(f"  Command: {' '.join(fixed_cmd)}\n")
    
    attempt = 1
    fixed_version = None
    while fixed_version is None:
        print(f"    [{time.strftime('%H:%M:%S')}] Attempt {attempt}: Starting command...")
        start_time = time.time()
        
        try:
            # NO TIMEOUT - let the command finish naturally
            # This is CRITICAL - must match test_docker_ready.py exactly
            result = subprocess.run(
                fixed_cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            elapsed = time.time() - start_time
            
            # Check if we got output
            if result.stdout.strip():
                fixed_version = result.stdout.strip()
                print(f"    [{time.strftime('%H:%M:%S')}] Attempt {attempt}: ✓ SUCCESS after {elapsed:.2f}s")
                print(f"    Output: {fixed_version}")
                break
            else:
                print(f"    [{time.strftime('%H:%M:%S')}] Attempt {attempt}: ○ No output after {elapsed:.2f}s")
                
                # Show stderr if present
                if result.stderr.strip():
                    print(f"      stderr: {result.stderr.strip()[:100]}")
                
                # Wait before next attempt
                print(f"    [{time.strftime('%H:%M:%S')}]   Waiting 2 seconds before next attempt...")
                time.sleep(2.0)
                attempt += 1
                
        except KeyboardInterrupt:
            print("\n\nCancelled by user")
            sys.exit(1)
    
    versions = {'vuln': vuln_version, 'fixed': fixed_version}
    
    # Step 5: Validate versions
    print(f"\n{'='*60}")
    print(f"  Step 5: Validating versions")
    print(f"{'='*60}\n")
    
    vuln_ok = '3.7.7' in vuln_version
    fixed_ok = '3.7.8' in fixed_version
    
    print(f"  Vulnerable version: {vuln_version}")
    print(f"    Expected: 3.7.7 {'✓' if vuln_ok else '✗'}")
    print(f"\n  Fixed version: {fixed_version}")
    print(f"    Expected: 3.7.8 {'✓' if fixed_ok else '✗'}")
    
    if not (vuln_ok and fixed_ok):
        print(f"\n{'='*60}")
        print("  [FAILURE] Version mismatch detected")
        print(f"{'='*60}\n")
        print("The images built are not the expected versions.")
        print("This indicates a problem with the Dockerfile or task.yml configuration.")
        sys.exit(1)
    
    # Step 6: Test with provided seed
    print(f"\n{'='*60}")
    print(f"  Step 6: Testing with provided seed")
    print(f"{'='*60}\n")
    
    result = run_command(
        [sys.executable, "-m", "scripts.bench", "evaluate", TASK_ID, "--seed", str(seed_path)],
        f"Running evaluation with {seed_path.name}",
        check=False
    )
    
    # Parse output for verdict
    output = result.stdout if hasattr(result, 'stdout') else ""
    
    # Determine success from output
    success = "success=True" in output
    vuln_crashes = success or "vuln_crashes=True" in output
    fixed_crashes = "fixed_crashes=True" in output
    
    # Create result dictionary
    verification_result = {
        "seed_path": str(seed_path),
        "seed_name": seed_path.name,
        "seed_size": seed_path.stat().st_size,
        "task_id": TASK_ID,
        "success": success,
        "vuln_crashes": vuln_crashes,
        "fixed_crashes": fixed_crashes,
        "vuln_version": vuln_version,
        "fixed_version": fixed_version,
        "timestamp": datetime.now().isoformat(),
        "output": output
    }
    
    # Save results if requested
    if args.save:
        output_dir = Path(args.output_dir) if args.output_dir else (repo_root / "runs" / "verifications")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"{timestamp}_{seed_path.stem}_verify.json"
        
        with open(output_file, 'w') as f:
            json.dump(verification_result, f, indent=2)
        
        print(f"\n📝 Results saved to: {output_file}")
    
    if success:
        print(f"\n{'='*60}")
        print("  ✓ SUCCESS - Seed is a valid exploit!")
        print(f"{'='*60}\n")
        print("  vuln_crashes=True, fixed_crashes=False")
        print(f"  The seed file {seed_path.name} works as expected!")
    else:
        print(f"\n{'='*60}")
        print("  ✗ FAILURE - Seed is NOT a valid exploit")
        print(f"{'='*60}\n")
        
        # Try to give more info
        if not vuln_crashes:
            print("  Vulnerable version does not crash")
            print("  This seed does not trigger the vulnerability")
        elif fixed_crashes:
            print("  Fixed version also crashes (false positive)")
            print("  This seed causes crashes in both versions")
        else:
            print("  Unable to determine crash status from output")
        
        print(f"\n  Review the output above for details.")
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print("VERIFICATION COMPLETE")
    print(f"{'='*60}\n")
    print(f"Seed: {seed_path}")
    print(f"Result: VALID EXPLOIT ✓")
    print(f"Vulnerable crashes: Yes")
    print(f"Fixed crashes: No")


if __name__ == "__main__":
    main()
