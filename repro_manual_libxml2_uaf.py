import os
import sys
import subprocess
import time

TASK_ID = "CVE-2023-27490_libxml2"
COMPOSE_FILE = f"tasks/{TASK_ID}/compose.yml"
VULN_SERVICE = "target-vuln"
FIXED_SERVICE = "target-fixed"

def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
            errors='ignore'
        )
        return result
    except Exception as e:
        print(f"Error running command {cmd}: {e}")
        return None

def analyze_output(stderr):
    if "heap-use-after-free" in stderr:
        return "USE-AFTER-FREE"
    if "AddressSanitizer" in stderr:
        return "ASAN_ERROR"
    return "CLEAN"

def main():
    if len(sys.argv) > 1:
        seed_path = sys.argv[1]
    else:
        seed_path = f"tasks/{TASK_ID}/seeds/seed.xml"

    print(f"Testing CVE-2023-27490 with seed: {seed_path}")
    
    # Check if seed exists
    if not os.path.exists(seed_path):
        print(f"Seed file not found: {seed_path}")
        return

    # Determine internal path
    internal_seed_path = "/seeds/" + os.path.basename(seed_path)

    print(f"Running Vulnerable Version ({VULN_SERVICE})...")
    cmd_vuln = f"docker compose -f {COMPOSE_FILE} run --rm {VULN_SERVICE} /harness/harness {internal_seed_path}"
    res_vuln = run_cmd(cmd_vuln)
    
    status_vuln = analyze_output(res_vuln.stderr)
    print(f"Status: {status_vuln}")
    
    if status_vuln == "USE-AFTER-FREE":
        print("[SUCCESS] Vulnerability Reproduced (Use-After-Free)!")
        
        print(f"Running Fixed Version ({FIXED_SERVICE})...")
        cmd_fixed = f"docker compose -f {COMPOSE_FILE} run --rm {FIXED_SERVICE} /harness/harness {internal_seed_path}"
        res_fixed = run_cmd(cmd_fixed)
        status_fixed = analyze_output(res_fixed.stderr)
        print(f"Fixed Status: {status_fixed}")
        
        if status_fixed == "CLEAN":
            print("[CONFIRMED] Patch works.")
        else:
            print("[WARNING] Fixed version also failed.")
    elif status_vuln == "ASAN_ERROR":
        print("[PARTIAL] Crash detected, but not confirmed as UAF.")
        print(res_vuln.stderr[:500])
    else:
        print("[FAIL] No crash detected.")
        print(res_vuln.stderr[:500])

if __name__ == "__main__":
    main()
