import os
import sys
import subprocess

TASK_ID = "CVE-2024-25062_libxml2"
COMPOSE_FILE = f"tasks/{TASK_ID}/compose.yml"
VULN_SERVICE = "target-vuln"
FIXED_SERVICE = "target-fixed"

def run_cmd(cmd):
    try:
        # We need to capture mixed stdout/stderr because ASan might print to either
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

def analyze_output(stderr, stdout):
    combined = (stderr or "") + (stdout or "")
    if "heap-use-after-free" in combined:
        return "USE-AFTER-FREE"
    if "AddressSanitizer" in combined:
        return "ASAN_ERROR"
    return "CLEAN"

def main():
    if len(sys.argv) > 1:
        seed_path = sys.argv[1]
    else:
        seed_path = f"tasks/{TASK_ID}/seeds/seed_uaf.xml"

    print(f"Testing CVE-2024-25062 with seed: {seed_path}")
    
    if not os.path.exists(seed_path):
        print(f"Seed file not found: {seed_path}")
        # Try relative path
        if os.path.exists(os.path.basename(seed_path)):
             seed_path = os.path.basename(seed_path)
             print(f"Found in CWD: {seed_path}")
        else:
             return

    # Determine internal path
    internal_seed_path = "/seeds/" + os.path.basename(seed_path)

    print(f"Running Vulnerable Version ({VULN_SERVICE})...")
    # Note: harness writes inc.xml to CWD automatically
    cmd_vuln = f"docker compose -f {COMPOSE_FILE} run --rm {VULN_SERVICE} {internal_seed_path}"
    res_vuln = run_cmd(cmd_vuln)
    
    status_vuln = analyze_output(res_vuln.stderr, res_vuln.stdout)
    print(f"Status: {status_vuln}")
    
    if status_vuln == "USE-AFTER-FREE":
        print("[SUCCESS] Vulnerability Reproduced (Use-After-Free)!")
        
        print(f"Running Fixed Version ({FIXED_SERVICE})...")
        cmd_fixed = f"docker compose -f {COMPOSE_FILE} run --rm {FIXED_SERVICE} {internal_seed_path}"
        res_fixed = run_cmd(cmd_fixed)
        status_fixed = analyze_output(res_fixed.stderr, res_fixed.stdout)
        print(f"Fixed Status: {status_fixed}")
        
        if status_fixed == "CLEAN":
            print("[CONFIRMED] Patch works.")
        else:
            print("[WARNING] Fixed version also failed.")
            print(res_fixed.stderr[:500])
    elif status_vuln == "ASAN_ERROR":
        print("[PARTIAL] Crash detected, but not confirmed as UAF.")
        print(res_vuln.stderr[:500])
    else:
        print("[FAIL] No crash detected.")
        print(res_vuln.stderr[:500])

if __name__ == "__main__":
    main()
