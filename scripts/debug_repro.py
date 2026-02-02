#!/usr/bin/env python3
import sys
import subprocess
from pathlib import Path

def debug_repro(task_id, seed_path):
    seed = Path(seed_path).resolve()
    if not seed.exists():
        print(f"Seed not found: {seed}")
        return

    print(f"Debugging {task_id} with seed {seed.name} ({seed.stat().st_size} bytes)...")
    
    # Construct compose file path
    repo_root = Path(__file__).parent.parent
    compose_file = repo_root / "tasks" / task_id / "compose.yml"
    
    cmd = [
        "docker", "compose", 
        "-f", str(compose_file),
        "run", "--rm", 
        "-v", f"{seed}:/input/seed.bin:ro",
        "target-vuln"
    ]
    
    print("Running command:", " ".join(cmd))
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )
    
    print("\n" + "="*40)
    print(f"EXIT CODE: {result.returncode}")
    print("="*40)
    print("STDOUT:")
    print(result.stdout)
    print("-" * 20)
    print("STDERR:")
    print(result.stderr)
    print("="*40)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 debug_repro.py <task_id> <seed_path>")
        sys.exit(1)
    
    debug_repro(sys.argv[1], sys.argv[2])
