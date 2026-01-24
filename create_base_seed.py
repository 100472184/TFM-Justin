#!/usr/bin/env python3
"""
Create deterministic base seed for CVE-2024-57970 libarchive fuzzing.

Creates a valid GNU TAR with:
- Long filename entry (type 'L') to exercise header_gnu_longlink()
- Deterministic metadata (mtime=0, uid=0, gid=0)
- 4KB of content for mutation surface
- Proper end markers (2x512 zero blocks)
"""

import tarfile
import io
import sys
from pathlib import Path

def create_base_seed(output_path: Path) -> bytes:
    """Create base.tar with GNU long filename."""
    
    # Create in-memory TAR
    tar_buffer = io.BytesIO()
    
    with tarfile.open(fileobj=tar_buffer, mode='w', format=tarfile.GNU_FORMAT) as tar:
        # Create file with long name (>= 159 chars to force longname helper)
        # Use exactly 159 'a' chars so with trailing NUL = 160 bytes
        long_filename = "a" * 159
        
        # Create TarInfo with deterministic metadata
        info = tarfile.TarInfo(name=long_filename)
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mode = 0o644
        info.type = tarfile.REGTYPE
        
        # 4KB of deterministic content
        content = b"BASESEED\n" * 455  # 455 * 9 = 4095 bytes
        content += b"END\n"  # Total 4099 bytes
        info.size = len(content)
        
        tar.addfile(info, io.BytesIO(content))
    
    # Get TAR bytes
    tar_bytes = tar_buffer.getvalue()
    
    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(tar_bytes)
    
    return tar_bytes

def validate_tar_structure(tar_bytes: bytes) -> dict:
    """Validate TAR structure and return diagnostic info."""
    results = {
        "size": len(tar_bytes),
        "aligned_512": len(tar_bytes) % 512 == 0,
        "ends_with_zeros": tar_bytes[-1024:] == b"\x00" * 1024,
        "members": []
    }
    
    # Parse members
    tar_buffer = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
        for member in tar.getmembers():
            results["members"].append({
                "name": member.name,
                "type": member.type,
                "size": member.size,
                "mtime": member.mtime,
                "uid": member.uid,
                "gid": member.gid
            })
    
    # Check for LongLink helper
    offset = 0
    while offset < len(tar_bytes) - 1024:
        block = tar_bytes[offset:offset+512]
        if block == b"\x00" * 512:
            break
        
        # Check if this is a LongLink header
        name = block[0:100].rstrip(b"\x00").decode('ascii', errors='ignore')
        typeflag = chr(block[156]) if block[156] != 0 else '0'
        
        if "LongLink" in name:
            results["longlink_found"] = {
                "name": name,
                "typeflag": typeflag,
                "offset": offset
            }
            
            # Parse size field
            size_field = block[124:136].rstrip(b"\x00 ").decode('ascii')
            try:
                declared_size = int(size_field, 8)
                results["longlink_found"]["declared_size"] = declared_size
                
                # Calculate blocks needed
                blocks_needed = (declared_size + 511) // 512
                results["longlink_found"]["blocks_needed"] = blocks_needed
            except ValueError:
                pass
        
        offset += 512
    
    return results

def run_bench_test(seed_path: Path, service: str) -> dict:
    """Run bench test and capture result."""
    import subprocess
    
    cmd = [
        sys.executable, "-m", "scripts.bench", "run",
        "CVE-2024-57970_libarchive",
        "--service", service,
        "--seed", str(seed_path)
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    
    return {
        "service": service,
        "exit_code": result.returncode,
        "stdout": result.stdout[-500:] if len(result.stdout) > 500 else result.stdout,
        "stderr": result.stderr[-500:] if len(result.stderr) > 500 else result.stderr
    }

def main():
    # Paths
    repo_root = Path(__file__).parent
    seed_path = repo_root / "tasks" / "CVE-2024-57970_libarchive" / "seeds" / "base.tar"
    
    print("=" * 70)
    print("Creating deterministic base seed for CVE-2024-57970")
    print("=" * 70)
    
    # Create seed
    print("\n[1/4] Creating base.tar...")
    tar_bytes = create_base_seed(seed_path)
    print(f"  ✓ Created: {seed_path}")
    print(f"  ✓ Size: {len(tar_bytes)} bytes")
    
    # Validate structure
    print("\n[2/4] Validating TAR structure...")
    validation = validate_tar_structure(tar_bytes)
    
    print(f"  ✓ Size: {validation['size']} bytes")
    print(f"  ✓ 512-byte aligned: {validation['aligned_512']}")
    print(f"  ✓ Ends with 1024 zero bytes: {validation['ends_with_zeros']}")
    
    if "longlink_found" in validation:
        ll = validation["longlink_found"]
        print(f"  ✓ LongLink helper found:")
        print(f"    - Name: {ll['name']}")
        print(f"    - Type: '{ll['typeflag']}'")
        print(f"    - Declared size: {ll.get('declared_size', 'N/A')} bytes")
        print(f"    - Blocks needed: {ll.get('blocks_needed', 'N/A')}")
    
    print(f"\n  Members in archive:")
    for i, member in enumerate(validation['members'], 1):
        print(f"    {i}. {member['name'][:50]}")
        print(f"       Type: {member['type']}, Size: {member['size']} bytes")
        print(f"       mtime={member['mtime']}, uid={member['uid']}, gid={member['gid']}")
    
    # Test with vulnerable version
    print("\n[3/4] Testing with vulnerable version (v3.7.7)...")
    try:
        vuln_result = run_bench_test(seed_path, "target-vuln")
        print(f"  Exit code: {vuln_result['exit_code']}")
        if vuln_result['exit_code'] not in [0, 1]:
            print(f"  ⚠ WARNING: Unexpected exit code!")
            print(f"  STDERR: {vuln_result['stderr']}")
        else:
            print(f"  ✓ Processes cleanly (no crash)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return 1
    
    # Test with fixed version
    print("\n[4/4] Testing with fixed version (v3.7.8)...")
    try:
        fixed_result = run_bench_test(seed_path, "target-fixed")
        print(f"  Exit code: {fixed_result['exit_code']}")
        if fixed_result['exit_code'] not in [0, 1]:
            print(f"  ⚠ WARNING: Unexpected exit code!")
            print(f"  STDERR: {fixed_result['stderr']}")
        else:
            print(f"  ✓ Processes cleanly (no crash)")
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return 1
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Base seed: {seed_path}")
    print(f"Size: {validation['size']} bytes ({validation['size'] // 512} blocks)")
    print(f"Valid structure: {validation['aligned_512'] and validation['ends_with_zeros']}")
    print(f"Vulnerable version: exit_code={vuln_result['exit_code']} {'✓' if vuln_result['exit_code'] in [0,1] else '✗'}")
    print(f"Fixed version: exit_code={fixed_result['exit_code']} {'✓' if fixed_result['exit_code'] in [0,1] else '✗'}")
    
    if vuln_result['exit_code'] in [0, 1] and fixed_result['exit_code'] in [0, 1]:
        print("\n✓ Base seed is VALID and ready for fuzzing!")
        return 0
    else:
        print("\n✗ Base seed validation FAILED - check output above")
        return 1

if __name__ == "__main__":
    sys.exit(main())
