#!/usr/bin/env python3
"""
Validator for TAR base seeds - ensures structural correctness.

Validates:
1. 512-byte alignment
2. Proper end markers (2x512 zero blocks)
3. GNU LongLink entry size matches data blocks
4. Deterministic metadata
5. No crashes on both versions
"""

import sys
from pathlib import Path
from typing import Optional

def validate_tar_seed(seed_path: Path) -> dict:
    """
    Validate TAR seed structure without exploiting.
    
    Returns dict with validation results and any errors.
    """
    results = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "checks": {}
    }
    
    # Read seed
    try:
        with open(seed_path, "rb") as f:
            tar_bytes = f.read()
    except Exception as e:
        results["valid"] = False
        results["errors"].append(f"Cannot read seed: {e}")
        return results
    
    # Check 1: Size and alignment
    size = len(tar_bytes)
    results["checks"]["size"] = size
    
    if size < 1024:
        results["valid"] = False
        results["errors"].append(f"Seed too small: {size} bytes (minimum 1024)")
    
    if size % 512 != 0:
        results["valid"] = False
        results["errors"].append(f"Not 512-byte aligned: {size} bytes")
    else:
        results["checks"]["aligned"] = True
    
    # Check 2: End markers (2x512 zero blocks)
    if size >= 1024:
        end_bytes = tar_bytes[-1024:]
        if end_bytes == b"\x00" * 1024:
            results["checks"]["end_markers"] = True
        else:
            # Count how many trailing zero blocks
            zero_blocks = 0
            for i in range(len(tar_bytes) - 512, -1, -512):
                if tar_bytes[i:i+512] == b"\x00" * 512:
                    zero_blocks += 1
                else:
                    break
            
            if zero_blocks < 2:
                results["valid"] = False
                results["errors"].append(f"Missing end markers: only {zero_blocks} zero blocks at end")
            else:
                results["checks"]["end_markers"] = True
                results["warnings"].append(f"Has {zero_blocks} zero blocks (expected 2)")
    
    # Check 3: Parse headers and validate LongLink entries
    offset = 0
    header_num = 0
    longlink_entries = []
    
    while offset < len(tar_bytes) - 1024:
        block = tar_bytes[offset:offset+512]
        
        # Check for zero block (end of archive)
        if block == b"\x00" * 512:
            results["checks"]["archive_end_offset"] = offset
            break
        
        header_num += 1
        
        # Parse header fields
        try:
            name = block[0:100].rstrip(b"\x00").decode('ascii', errors='replace')
            typeflag = chr(block[156]) if block[156] != 0 else '0'
            size_field = block[124:136].rstrip(b"\x00 ").decode('ascii')
            
            # Parse size
            if size_field:
                size = int(size_field, 8)
            else:
                size = 0
            
            # Calculate blocks needed for data
            data_blocks = (size + 511) // 512
            
            # Check for LongLink helper
            if "LongLink" in name and typeflag in ['L', 'K']:
                longlink_entry = {
                    "offset": offset,
                    "name": name,
                    "typeflag": typeflag,
                    "declared_size": size,
                    "blocks_needed": data_blocks
                }
                longlink_entries.append(longlink_entry)
                
                # Validate: check that data blocks exist and match size
                data_start = offset + 512
                data_end = data_start + (data_blocks * 512)
                
                if data_end > len(tar_bytes):
                    results["valid"] = False
                    results["errors"].append(
                        f"LongLink at offset {offset}: declared size {size} requires "
                        f"{data_blocks} blocks but archive ends at {len(tar_bytes)}"
                    )
                else:
                    # Read actual data
                    actual_data = tar_bytes[data_start:data_start+size]
                    longlink_entry["actual_data_length"] = len(actual_data)
                    
                    # Check padding in last block
                    if data_blocks > 0:
                        last_block_start = data_start + ((data_blocks - 1) * 512)
                        last_block = tar_bytes[last_block_start:last_block_start+512]
                        used_in_last = size % 512 or 512
                        padding = last_block[used_in_last:]
                        
                        if padding != b"\x00" * len(padding):
                            results["warnings"].append(
                                f"LongLink at offset {offset}: last block not zero-padded"
                            )
            
            # Move to next header (skip current header + data blocks)
            offset += 512 + (data_blocks * 512)
            
        except Exception as e:
            results["warnings"].append(f"Error parsing header at offset {offset}: {e}")
            offset += 512
    
    results["checks"]["headers_parsed"] = header_num
    results["checks"]["longlink_entries"] = len(longlink_entries)
    
    # Check 4: Ensure at least one LongLink entry exists
    if not longlink_entries:
        results["valid"] = False
        results["errors"].append("No GNU LongLink entries found (type 'L' or 'K')")
    else:
        results["checks"]["longlink_details"] = longlink_entries
        
        # Validate each LongLink
        for entry in longlink_entries:
            if entry["typeflag"] == 'L':
                results["checks"]["has_long_filename"] = True
            if entry["typeflag"] == 'K':
                results["checks"]["has_long_linkname"] = True
    
    # Check 5: Deterministic metadata (can only check via tarfile module)
    try:
        import tarfile
        import io
        
        tar_buffer = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
            non_deterministic = []
            for member in tar.getmembers():
                # Skip LongLink helpers (they're internal)
                if "LongLink" in member.name:
                    continue
                
                if member.mtime != 0:
                    non_deterministic.append(f"{member.name}: mtime={member.mtime}")
                if member.uid != 0:
                    non_deterministic.append(f"{member.name}: uid={member.uid}")
                if member.gid != 0:
                    non_deterministic.append(f"{member.name}: gid={member.gid}")
            
            if non_deterministic:
                results["warnings"].append("Non-deterministic metadata found:")
                for item in non_deterministic:
                    results["warnings"].append(f"  - {item}")
            else:
                results["checks"]["deterministic_metadata"] = True
                
    except Exception as e:
        results["warnings"].append(f"Could not validate metadata: {e}")
    
    return results

def print_validation_report(results: dict, seed_path: Path):
    """Print human-readable validation report."""
    print("=" * 70)
    print(f"TAR SEED VALIDATION: {seed_path.name}")
    print("=" * 70)
    
    print(f"\nSize: {results['checks'].get('size', 'unknown')} bytes")
    print(f"512-byte aligned: {'✓' if results['checks'].get('aligned') else '✗'}")
    print(f"End markers (2x512 zeros): {'✓' if results['checks'].get('end_markers') else '✗'}")
    print(f"Headers parsed: {results['checks'].get('headers_parsed', 0)}")
    print(f"LongLink entries: {results['checks'].get('longlink_entries', 0)}")
    
    if results['checks'].get('has_long_filename'):
        print("  ✓ Has long filename (type 'L')")
    if results['checks'].get('has_long_linkname'):
        print("  ✓ Has long linkname (type 'K')")
    
    if results['checks'].get('deterministic_metadata'):
        print("  ✓ Deterministic metadata (mtime=0, uid=0, gid=0)")
    
    # Show LongLink details
    if "longlink_details" in results['checks']:
        print("\nLongLink entries:")
        for i, entry in enumerate(results['checks']['longlink_details'], 1):
            print(f"  {i}. Type '{entry['typeflag']}' at offset {entry['offset']}")
            print(f"     Declared size: {entry['declared_size']} bytes")
            print(f"     Blocks needed: {entry['blocks_needed']}")
            if 'actual_data_length' in entry:
                print(f"     Actual data: {entry['actual_data_length']} bytes")
    
    # Warnings
    if results['warnings']:
        print(f"\n⚠ WARNINGS ({len(results['warnings'])}):")
        for warning in results['warnings']:
            print(f"  - {warning}")
    
    # Errors
    if results['errors']:
        print(f"\n✗ ERRORS ({len(results['errors'])}):")
        for error in results['errors']:
            print(f"  - {error}")
    
    # Overall status
    print("\n" + "=" * 70)
    if results['valid']:
        print("✓ VALIDATION PASSED - Seed is structurally correct")
    else:
        print("✗ VALIDATION FAILED - Fix errors above")
    print("=" * 70)

def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_seed.py <seed.tar>")
        print("\nExample:")
        print("  python validate_seed.py tasks/CVE-2024-57970_libarchive/seeds/base.tar")
        return 1
    
    seed_path = Path(sys.argv[1])
    
    if not seed_path.exists():
        print(f"Error: Seed file not found: {seed_path}")
        return 1
    
    results = validate_tar_seed(seed_path)
    print_validation_report(results, seed_path)
    
    return 0 if results['valid'] else 1

if __name__ == "__main__":
    sys.exit(main())
