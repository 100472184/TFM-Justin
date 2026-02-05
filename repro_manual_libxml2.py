import os
import subprocess
import time

def run_cmd(cmd, cwd=None):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=False,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
            errors='ignore'
        )
        return result
    except Exception as e:
        print(f"Error running command {cmd}: {e}")
        return None

def analyze_asan_output(stderr: str) -> dict:
    """Analyze ASan output and categorize the error"""
    result = {
        'has_asan_error': False,
        'error_type': None,
        'is_double_free': False,
        'is_use_after_free': False,
        'is_bad_free': False,
        'in_dict_code': False
    }
    
    if 'AddressSanitizer' not in stderr:
        return result
    
    result['has_asan_error'] = True
    
    # Detect error type
    lower_err = stderr.lower()
    if 'double-free' in lower_err or 'attempting double-free' in stderr:
        result['error_type'] = 'double-free'
        result['is_double_free'] = True
    elif 'heap-use-after-free' in lower_err:
        result['error_type'] = 'use-after-free'
        result['is_use_after_free'] = True
    elif 'bad-free' in lower_err or 'attempting free on address which was not malloc' in stderr:
        result['error_type'] = 'invalid-free'
        result['is_bad_free'] = True
    elif 'heap-buffer-overflow' in lower_err:
        result['error_type'] = 'buffer-overflow'
    
    # Check if error is in dict code (CVE-specific)
    if any(func in stderr for func in ['xmlDict', 'dict.c']):
        result['in_dict_code'] = True
    
    return result

def main():
    print("======================================================================")
    print("Multi-Seed Verification for CVE-2023-29469 (LibXML2 Double Free)")
    print("======================================================================")
    
    seeds_dir = "tasks/CVE-2023-29469_libxml2/seeds"
    seeds_to_test = [
        "seed_namespace_collision.xml",
        "seed_massive_empty_attrs.xml",
        "seed_empty_prefix_heavy.xml",
        "seed_attrs_empty_ns.xml",
        "seed_deep_nesting_empty.xml"
    ]
    
    # Ensure they exist
    valid_seeds = []
    for s in seeds_to_test:
        path = os.path.join(seeds_dir, s)
        if os.path.exists(path):
            valid_seeds.append(s)
        else:
            print(f"[!] Warning: Seed {s} not found, skipping.")
    
    if not valid_seeds:
        print("No validation seeds found. Please create them first.")
        return

    # Build first (just in case)
    print("\n[+] Determining Docker image status...")
    # Assuming already built based on previous success, but let's just run
    
    RUNS_PER_SEED = 20
    
    for seed_name in valid_seeds:
        seed_path = f"/seeds/{seed_name}" # Path inside container
        print(f"\nTesting with: {seed_name}")
        print("-" * 60)
        
        vuln_crashes = 0
        vuln_double_free = 0
        
        # We need to mount the specific seed file or ensure the whole dir is mounted
        # compose.yml mounts ./seeds:/seeds, so /seeds/seed_name works
        
        cmd = f"docker compose -f tasks/CVE-2023-29469_libxml2/compose.yml run --rm target-vuln /harness/harness {seed_path}"
        
        for i in range(1, RUNS_PER_SEED + 1):
            res = run_cmd(cmd)
            stdout = res.stdout or ""
            stderr = res.stderr or ""
            combined = stdout + stderr
            
            analysis = analyze_asan_output(stderr)
            
            if analysis['has_asan_error'] or res.returncode in [139, 134]:
                vuln_crashes += 1
                
                msg = "ASan error"
                if analysis['is_double_free']:
                    msg = "DOUBLE-FREE"
                    vuln_double_free += 1
                elif analysis['is_use_after_free']:
                    msg = "USE-AFTER-FREE"
                elif analysis['is_bad_free']:
                    msg = "INVALID-FREE"
                
                print(f"  Run {i}: X {msg} detected!")
            else:
                pass 
                # print(f"  Run {i}: Clean")

        print(f"  Results: {vuln_crashes}/{RUNS_PER_SEED} crashes ({vuln_double_free} double-free)")
        
        if vuln_crashes > 0:
            print(f"  [SUCCESS] {seed_name} triggers the vulnerability!")
            
            # Verify Fixed
            print("  Verifying with FIXED version (10 runs)...")
            fixed_crashes = 0
            cmd_fixed = f"docker compose -f tasks/CVE-2023-29469_libxml2/compose.yml run --rm target-fixed /harness/harness {seed_path}"
            
            for j in range(1, 11):
                res_f = run_cmd(cmd_fixed)
                analysis_f = analyze_asan_output(res_f.stderr or "")
                if analysis_f['has_asan_error'] or res_f.returncode in [139, 134]:
                    fixed_crashes += 1
            
            if fixed_crashes == 0:
                print("  [CONFIRMED] Fixed version is clean (0/10 crashes).")
                print(f"  -> {seed_name} is a VALID REPRODUCTION.")
                return # Stop at first widespread success
            else:
                print(f"  [WARNING] Fixed version also crashed ({fixed_crashes}/10).")
        else:
            print("  No reliable crash detected.")

    print("\n======================================================================")
    print("Run completed.")

if __name__ == "__main__":
    main()
