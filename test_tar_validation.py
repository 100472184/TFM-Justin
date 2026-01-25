"""
Test script to verify that tarfile validation produces descriptive error messages.
"""
import tempfile
import tarfile
from pathlib import Path

def validate_tar_structure(seed_bytes: bytes) -> tuple[bool, str]:
    """Same validation as pipeline.py"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".tar") as tmp:
        tmp.write(seed_bytes)
        tmp_path = tmp.name
    
    try:
        # Use 'r:' mode (uncompressed) to avoid auto-detection issues
        with tarfile.open(tmp_path, 'r:') as tar:
            members = tar.getmembers()
            if len(members) == 0:
                return False, "TAR has no members (empty or invalid)"
        return True, ""
    except tarfile.ReadError as e:
        error_str = str(e).lower()
        # "empty header" indicates truncation - OK for exploit
        if "empty header" in error_str or "truncated" in error_str:
            return True, ""
        # "bad checksum" indicates corruption - REJECT
        if "bad checksum" in error_str or "invalid header" in error_str:
            return False, f"Corrupted TAR structure: {str(e)[:100]}"
        return False, f"Invalid TAR format: {str(e)[:100]}"
    except tarfile.TarError as e:
        return False, f"TAR error: {str(e)[:100]}"
    except EOFError:
        return True, ""  # Truncated - acceptable
    except Exception as e:
        return True, f"Warning: validation error {str(e)[:100]}"
    finally:
        try:
            Path(tmp_path).unlink()
        except:
            pass

# Test 1: Valid base.tar
print("Test 1: Valid base.tar")
base_path = Path("tasks/CVE-2024-57970_libarchive/seeds/base.tar")
if base_path.exists():
    base_bytes = base_path.read_bytes()
    valid, error = validate_tar_structure(base_bytes)
    print(f"  Result: valid={valid}, error='{error}'")
else:
    print("  ✗ base.tar not found")

# Test 2: Corrupted TAR with "deadbeef" at start
print("\nTest 2: Corrupted TAR (deadbeef at offset 0)")
if base_path.exists():
    corrupted = bytearray(base_path.read_bytes()[:1024])
    corrupted[0:4] = b'\xde\xad\xbe\xef'
    valid, error = validate_tar_structure(bytes(corrupted))
    print(f"  Result: valid={valid}, error='{error}'")

# Test 3: Valid truncation
print("\nTest 3: Valid truncation (1024 bytes)")
if base_path.exists():
    truncated = base_path.read_bytes()[:1024]
    valid, error = validate_tar_structure(truncated)
    print(f"  Result: valid={valid}, error='{error}'")

# Test 4: Heavily truncated (768 bytes)
print("\nTest 4: Heavily truncated (768 bytes)")
if base_path.exists():
    truncated = base_path.read_bytes()[:768]
    valid, error = validate_tar_structure(truncated)
    print(f"  Result: valid={valid}, error='{error}'")

# Test 5: Empty file
print("\nTest 5: Empty file")
valid, error = validate_tar_structure(b"")
print(f"  Result: valid={valid}, error='{error}'")
