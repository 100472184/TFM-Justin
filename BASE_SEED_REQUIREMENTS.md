# Base Seed Requirements for CVE-2024-57970 (libarchive)

## Overview
A base seed is the **starting point** for fuzzing. It should:
1. Be **valid enough** to process without immediate crash
2. **Trigger the vulnerable code path** (GNU longlink handling)
3. **NOT exploit the vulnerability** (that's what fuzzing discovers)
4. Provide **meaningful data to mutate**

## Current base.tar Analysis

**Size:** 10,240 bytes (10 KB = 20 × 512-byte blocks)

**Structure:**
```
Offset 0x00-0x1FF (512 bytes): GNU Long Link Header (type 'L')
  - Name: "././@LongLink"
  - Type: 'L' (0x4C at offset 0x9C)
  - Size: "0000240" (160 bytes in octal = 0xA0 bytes)
  - Format: "ustar  " (GNU tar format)

Offset 0x200-0x2FF (512 bytes): Long linkname data block
  - Contains 160 bytes of linkname + padding

Offset 0x300-0x4FF (512 bytes): Regular file header
  - References the long linkname from above

Offset 0x500-0x27FF: File data blocks
  - 9,728 bytes of actual file content

Total: 20 blocks × 512 = 10,240 bytes
```

**Validation Test:**
```powershell
python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed "tasks\CVE-2024-57970_libarchive\seeds\base.tar"
# Expected: exit_code=0 (processes cleanly, no crash)

python -m scripts.bench run CVE-2024-57970_libarchive --service target-fixed --seed "tasks\CVE-2024-57970_libarchive\seeds\base.tar"
# Expected: exit_code=0 (processes cleanly, no crash)
```

## Required Characteristics for Good Base Seed

### 1. Must Be Valid TAR Structure
- **512-byte aligned blocks** (TAR uses 512-byte records)
- **Valid TAR header** at offset 0:
  * Name field (100 bytes)
  * Mode, uid, gid fields (octal ASCII)
  * Size field (octal ASCII, 11 bytes)
  * Checksum field (valid for header)
  * Type flag (0=file, 5=directory, K/L=GNU longlink)
  * Magic: "ustar" or "ustar  " (GNU format)

### 2. Must Trigger Vulnerable Code Path
For **CVE-2024-57970** specifically:
- **MUST contain GNU Long Link entry** (type 'K' or 'L')
  * Type 'K' = long linkname
  * Type 'L' = long filename
- **Size field must be valid** (parseable octal)
- **Must have data blocks** following the header
- **Should be complete** (not truncated initially)

### 3. Must NOT Crash Initially
- Both vulnerable AND fixed versions should process without error
- Exit code should be 0 (success) or 1 (benign error like "empty archive")
- **NO segfaults, NO ASan errors** with base seed
- This proves the seed exercises the code path without exploiting

### 4. Size Recommendations
- **Minimum:** 1,024 bytes (2 TAR blocks)
  * Too small = limited mutation space
- **Optimal:** 3,072 - 10,240 bytes (6-20 TAR blocks)
  * Enough data for meaningful mutations
  * Not too large (fuzzing iterations stay fast)
- **Maximum:** 50,000 bytes
  * Larger = slower iteration time

### 5. Content Guidelines
- **Structured data** (TAR headers) is better than random bytes
- **Include the vulnerable structure:**
  * GNU longlink header (type K/L)
  * Size field that matches data blocks
  * Linkname data blocks (multiple for testing)
- **Variation points** for mutation:
  * Size fields (truncation triggers overflow)
  * Name fields (boundary testing)
  * Data block boundaries (partial data scenarios)

## How to Create a Good Base Seed

### Option A: Generate with Python tarfile
```python
import tarfile
import io

# Create in-memory TAR
tar_buffer = io.BytesIO()
with tarfile.open(fileobj=tar_buffer, mode='w', format=tarfile.GNU_FORMAT) as tar:
    # Create a file with a very long name to trigger GNU longlink
    long_name = "a" * 150  # Longer than 100 chars forces GNU longlink
    
    info = tarfile.TarInfo(name=long_name)
    info.size = 1024  # 1KB of data
    data = b"test data\n" * 100
    
    tar.addfile(info, io.BytesIO(data))

# Get TAR bytes
tar_bytes = tar_buffer.getvalue()

# Save to file
with open("base.tar", "wb") as f:
    f.write(tar_bytes)
```

### Option B: Use Existing Valid TAR
```bash
# Create a valid TAR with long filename
echo "test content" > test.txt
tar --format=gnu -cf base.tar test.txt

# Verify it's valid
tar -tf base.tar  # Should list files without error
```

### Option C: Hand-Craft Binary (Advanced)
```python
import struct

def create_tar_header(name, size, typeflag=b'0'):
    header = bytearray(512)
    
    # Name (100 bytes)
    header[0:len(name)] = name.encode('ascii')
    
    # Mode (8 bytes) - "0000644\0"
    header[100:108] = b"0000644\0"
    
    # UID/GID (8 bytes each) - "0000000\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    
    # Size (12 bytes) - octal
    size_octal = f"{size:011o}\0".encode('ascii')
    header[124:136] = size_octal
    
    # Mtime (12 bytes) - "00000000000\0"
    header[136:148] = b"00000000000\0"
    
    # Checksum (8 bytes) - spaces initially
    header[148:156] = b"        "
    
    # Typeflag (1 byte)
    header[156] = typeflag[0]
    
    # Magic (6 bytes) + Version (2 bytes)
    header[257:263] = b"ustar "
    header[263:265] = b" \0"
    
    # Calculate checksum
    checksum = sum(header)
    checksum_str = f"{checksum:06o}\0 ".encode('ascii')
    header[148:156] = checksum_str
    
    return bytes(header)

# Create GNU long link TAR
header = create_tar_header("././@LongLink", 160, b'L')
data = (b"a" * 150 + b"\0").ljust(512, b"\0")  # Long filename padded to block

with open("base.tar", "wb") as f:
    f.write(header)
    f.write(data)
    # Add file header + data...
```

## Validation Checklist

✅ **Both versions process without crash:**
```powershell
python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed base.tar
# Must return exit_code=0 or exit_code=1 (no 139, no ASan)

python -m scripts.bench run CVE-2024-57970_libarchive --service target-fixed --seed base.tar
# Must return exit_code=0 or exit_code=1 (no crashes)
```

✅ **Contains target structure:**
```powershell
# Check for GNU longlink marker
Get-Content base.tar -Encoding Byte -TotalCount 512 | Format-Hex
# Should show "././@LongLink" at offset 0x00
# Should show type 'L' (0x4C) or 'K' (0x4B) at offset ~0x9C
# Should show "ustar" at offset ~0x101
```

✅ **Correct size:**
```powershell
(Get-Item base.tar).Length
# Should be multiple of 512 (TAR block size)
# Recommended: 3072 - 10240 bytes
```

✅ **Triggers vulnerable function:**
```bash
# The vulnerable function is header_gnu_longlink()
# It's only called when processing type 'K' or 'L' entries
# Verify by reading libarchive source or using debugger
```

## Common Mistakes

❌ **Using random bytes:**
```python
# WRONG - not valid TAR structure
with open("base.tar", "wb") as f:
    f.write(os.urandom(10240))
```

❌ **Using exploit as base seed:**
```python
# WRONG - base seed should NOT crash
# base_truncated.tar (3072 bytes) is an EXPLOIT, not a base seed
```

❌ **Too small:**
```python
# WRONG - only header, no data
with open("base.tar", "wb") as f:
    f.write(create_tar_header("test", 0))  # Only 512 bytes
```

❌ **Wrong format:**
```python
# WRONG - old POSIX TAR doesn't have GNU longlink
tar --format=posix -cf base.tar test.txt  # Won't trigger vulnerability
```

## Summary for Agent

**Provide to agent:**
```
Create a base seed (base.tar) for CVE-2024-57970 libarchive fuzzing with these requirements:

1. Size: 3,072 - 10,240 bytes (multiple of 512)

2. Structure:
   - Must be valid TAR format (512-byte blocks)
   - Must use GNU tar format (not POSIX)
   - Must contain GNU Long Link entry (type 'L' at byte 0x9C)
   - Name field: "././@LongLink"
   - Size field: Valid octal number (e.g., "0000240" = 160 bytes)
   - Magic: "ustar  " (with spaces)

3. Validation:
   - Both vulnerable (v3.7.7) and fixed (v3.7.8) versions must process without crash
   - Exit code must be 0 (success) - NOT 139 (segfault)
   - No ASan errors should appear

4. Data:
   - After header (512 bytes): linkname data block(s)
   - Followed by regular file header and data
   - Total must be complete (not truncated)

5. Test command:
   python -m scripts.bench run CVE-2024-57970_libarchive --service target-vuln --seed base.tar
   Expected: exit_code=0

The base seed is NOT an exploit - fuzzing will mutate it to create exploits.
The current base.tar (10,240 bytes) is VALID and should be kept if already working.
```

## Current Status

**Current base.tar:** ✅ **VALID**
- 10,240 bytes (20 TAR blocks)
- Contains GNU long link structure
- Type 'L' present
- Processes cleanly on both versions
- Good starting point for fuzzing

**DO NOT REPLACE unless:**
- Testing shows it crashes on base seed (should not)
- Need different truncation points
- Want to explore different TAR structures
