#!/usr/bin/env python3
"""
Complete cleanup and verification workflow for CVE-2024-57970 testing.

This script implements the full sequence discovered during debugging:
1. Complete Docker cleanup (down + prune)
2. Rebuild images from scratch
3. Wait for images to be ready (with retry logic)
4. Validate versions
5. Test with known exploit

Usage:
    python test_workflow.py [--skip-test]
    
Options:
    --skip-test    Skip the final exploit test (only verify images)
"""
from __future__ import annotations
import argparse
import subprocess
import sys
from pathlib import Path

# Add repo root to path
repo_root = Path(__file__).parent
sys.path.insert(0, str(repo_root))

from scripts.lib.docker_readiness import verify_task_images_ready


TASK_ID = "CVE-2024-57970_libarchive"
COMPOSE_FILE = f"tasks/{TASK_ID}/compose.yml"
KNOWN_EXPLOIT = f"tasks/{TASK_ID}/seeds/final_base.tar"


def run_command(cmd: list[str], description: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and print its description."""
    print(f"\n{'='*60}")
    print(f"  {description}")
    print(f"{'='*60}")
    print(f"$ {' '.join(cmd)}\n")
    
    result = subprocess.run(cmd, check=False, text=True)
    
    if check and result.returncode != 0:
        print(f"\n[ERROR] Command failed with exit code {result.returncode}")
        sys.exit(1)
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Complete Docker cleanup and verification workflow"
    )
    parser.add_argument(
        "--skip-test",
        action="store_true",
        help="Skip final exploit test (only verify images)"
    )
    args = parser.parse_args()
    
    print(f"""
{'='*60}
CVE-2024-57970 Complete Test Workflow
{'='*60}

This script will:
1. Destroy all Docker images and volumes
2. Clean Docker system cache
3. Rebuild images from scratch
4. Verify images are ready (with automatic retry)
5. Validate versions (vuln=3.7.7, fixed=3.7.8)
6. {'Test with known exploit' if not args.skip_test else 'Skip exploit test'}

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
    
    # Step 4: Verify images are ready with retry logic
    print(f"\n{'='*60}")
    print(f"  Step 4: Verifying images are ready (with retry)")
    print(f"{'='*60}\n")
    
    print("  This may take 2-5 attempts per image (normal Docker startup delay)...\n")
    
    images_ready, versions = verify_task_images_ready(
        TASK_ID,
        max_attempts=5,
        retry_delay=1.0,
        verbose=True
    )
    
    if not images_ready:
        print(f"\n{'='*60}")
        print("  [FAILURE] Images not responding after 5 attempts")
        print(f"{'='*60}\n")
        print("Possible issues:")
        print("  - Docker Desktop not running properly")
        print("  - WSL2 backend issues (Windows)")
        print("  - Insufficient resources")
        print("\nSuggestions:")
        print("  - Restart Docker Desktop")
        print("  - Check: wsl --status (Windows)")
        print("  - Check: docker info")
        sys.exit(1)
    
    # Step 5: Validate versions
    print(f"\n{'='*60}")
    print(f"  Step 5: Validating versions")
    print(f"{'='*60}\n")
    
    vuln_version = versions.get('vuln', '')
    fixed_version = versions.get('fixed', '')
    
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
    
    # Step 6: Test with known exploit (optional)
    if not args.skip_test:
        print(f"\n{'='*60}")
        print(f"  Step 6: Testing with known exploit")
        print(f"{'='*60}\n")
        
        result = run_command(
            [sys.executable, "-m", "scripts.bench", "evaluate", TASK_ID, "--seed", KNOWN_EXPLOIT],
            "Running evaluation with final_base.tar",
            check=False
        )
        
        # Parse output for verdict
        output = result.stdout if hasattr(result, 'stdout') else ""
        
        if "success=True" in output:
            print(f"\n{'='*60}")
            print("  ✓ SUCCESS - Exploit works as expected")
            print(f"{'='*60}\n")
            print("  vuln_crashes=True, fixed_crashes=False")
            print("  Docker images are fully functional and validated!")
        else:
            print(f"\n{'='*60}")
            print("  ✗ FAILURE - Exploit test failed")
            print(f"{'='*60}\n")
            print("Output suggests:")
            if "success=False" in output:
                if "vuln_crashes=False" in output:
                    print("  - Vulnerable version is not crashing (unexpected)")
                if "fixed_crashes=True" in output:
                    print("  - Fixed version is crashing (unexpected)")
            print("\nThis should NOT happen after proper rebuild + readiness check.")
            print("Possible causes:")
            print("  - Exploit file corrupted")
            print("  - Docker runtime issues")
            sys.exit(1)
    else:
        print(f"\n{'='*60}")
        print("  Step 6: Skipped (--skip-test flag)")
        print(f"{'='*60}\n")
    
    # Success summary
    print(f"\n{'='*60}")
    print("  WORKFLOW COMPLETE ✓")
    print(f"{'='*60}\n")
    print("Docker images are:")
    print("  ✓ Built from scratch")
    print("  ✓ Fully initialized and responding")
    print("  ✓ Correct versions (vuln=3.7.7, fixed=3.7.8)")
    if not args.skip_test:
        print("  ✓ Validated with known exploit")
    print("\nYou can now safely run:")
    print(f"  python -m agents.openhands_llama3.run --task-id {TASK_ID} --level L2 --max-iters 15")
    print("\nOr test manually:")
    print(f"  python -m scripts.bench evaluate {TASK_ID} --seed <your-seed>")
    print()


if __name__ == "__main__":
    main()
