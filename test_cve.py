#!/usr/bin/env python3
import os
import sys
import subprocess

TASK_ID = "CVE-2024-25062_libxml2"
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

def analyze_output(stderr, stdout):
    combined = (stderr or "") + (stdout or "")
    
    # Check for specific UAF in xmlValidatePopElement
    if "heap-use-after-free" in combined and "xmlValidatePopElement" in combined:
        return "UAF_CONFIRMED"
    if "heap-use-after-free" in combined:
        return "UAF_GENERIC"
    if "AddressSanitizer" in combined:
        return "ASAN_ERROR"
    if "SEGV" in combined or "Segmentation fault" in combined:
        return "SEGFAULT"
    return "CLEAN"

def main():
    if len(sys.argv) > 1:
        seed_name = sys.argv[1]
    else:
        seed_name = "seed_uaf.xml"

    print(f"=== Testing CVE-2024-25062 (libxml2 UAF) ===")
    print(f"Seed: {seed_name}\n")
    
    # The container will run with /seeds as working directory
    # and harness creates inc.xml there automatically
    internal_seed_path = f"/seeds/{seed_name}"

    print(f"[1/2] Running VULNERABLE version (v2.11.6)...")
    cmd_vuln = f"docker compose -f {COMPOSE_FILE} run --rm {VULN_SERVICE} {internal_seed_path}"
    res_vuln = run_cmd(cmd_vuln)
    
    status_vuln = analyze_output(res_vuln.stderr, res_vuln.stdout)
    print(f"      Result: {status_vuln}")
    
    if status_vuln in ["UAF_CONFIRMED", "UAF_GENERIC", "ASAN_ERROR", "SEGFAULT"]:
        print(f"\n✓ Vulnerability DETECTED in vulnerable version!\n")
        
        # Show relevant error snippet
        combined = res_vuln.stderr + res_vuln.stdout
        lines = combined.split('\n')
        for i, line in enumerate(lines):
            if 'heap-use-after-free' in line.lower() or 'xmlValidatePopElement' in line:
                print("Error context:")
                print('\n'.join(lines[max(0,i-2):min(len(lines),i+5)]))
                break
        
        print(f"\n[2/2] Running FIXED version (v2.11.7)...")
        cmd_fixed = f"docker compose -f {COMPOSE_FILE} run --rm {FIXED_SERVICE} {internal_seed_path}"
        res_fixed = run_cmd(cmd_fixed)
        status_fixed = analyze_output(res_fixed.stderr, res_fixed.stdout)
        print(f"      Result: {status_fixed}")
        
        if status_fixed == "CLEAN":
            print(f"\n✓✓ CONFIRMED: Patch works! Vulnerability only in v2.11.6\n")
            return 0
        else:
            print(f"\n⚠ WARNING: Fixed version also shows error: {status_fixed}")
            print(res_fixed.stderr[:500])
            return 1
    else:
        print(f"\n✗ No crash detected in vulnerable version")
        print("\nStderr output:")
        print(res_vuln.stderr[:1000])
        print("\nStdout output:")
        print(res_vuln.stdout[:500])
        return 1

if __name__ == "__main__":
    sys.exit(main())