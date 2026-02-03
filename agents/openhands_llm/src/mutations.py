"""Seed mutation operations for fuzzing."""
from __future__ import annotations
from typing import List, Dict

MAX_SEED_SIZE = 20 * 1024 * 1024  # 20MB limit (needed for CVE-2023-39804)


def validate_hex_string(hex_str: str, operation: str) -> None:
    """Validate hex string has even length before fromhex()."""
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Invalid hex in {operation}: {hex_str} (odd length: {len(hex_str)} chars)")


def apply_mutations(seed_bytes: bytes, mutations: List[Dict]) -> bytes:
    """
    Apply a list of mutation operations to seed bytes.
    
    Supported operations:
    - append_bytes: {"op": "append_bytes", "hex": "deadbeef"}
    - flip_bit: {"op": "flip_bit", "offset": 123, "bit": 5}
    - overwrite_range: {"op": "overwrite_range", "offset": 10, "hex": "cafebabe"}
    - truncate: {"op": "truncate", "new_len": 200}
    - repeat_range: {"op": "repeat_range", "offset": 20, "length": 40, "times": 3}
    - insert_repeated_bytes: {"op": "insert_repeated_bytes", "offset": 20, "hex": "41", "times": 1000}
    """
    result = bytearray(seed_bytes)
    
    for mut in mutations:
        op = mut.get("op", "")
        
        if op == "append_bytes":
            hex_str = mut.get("hex", "").replace(" ", "")
            if not hex_str:
                continue
            if len(hex_str) % 2 != 0:
                raise ValueError(f"Invalid hex in append_bytes: {hex_str} (odd length: {len(hex_str)} chars)")
            try:
                new_bytes = bytes.fromhex(hex_str)
                result.extend(new_bytes)
            except ValueError as e:
                raise ValueError(f"Invalid hex in append_bytes: {hex_str}") from e
        
        elif op == "flip_bit":
            offset = mut.get("offset", 0)
            bit = mut.get("bit", 0)
            if offset < 0 or offset >= len(result):
                raise ValueError(f"flip_bit offset {offset} out of range [0, {len(result)})")
            if bit < 0 or bit > 7:
                raise ValueError(f"flip_bit bit {bit} must be in [0, 7]")
            result[offset] ^= (1 << bit)
        
        elif op == "overwrite_range":
            offset = mut.get("offset", 0)
            hex_str = mut.get("hex", "").replace(" ", "")
            if not hex_str:
                continue
            if len(hex_str) % 2 != 0:
                raise ValueError(f"Invalid hex in overwrite_range: {hex_str} (odd length: {len(hex_str)} chars)")
            try:
                new_bytes = bytes.fromhex(hex_str)
            except ValueError as e:
                raise ValueError(f"Invalid hex in overwrite_range: {hex_str}") from e
            
            # Auto-expand: If offset is past end, fill with nulls
            if offset > len(result):
                result.extend(b'\x00' * (offset - len(result)))
            
            # Allow offset to be at end of file (for appending) or within file
            if offset < 0: # Still reject negative
                raise ValueError(f"overwrite_range offset {offset} must be >= 0")
            
            # FIXED: Extend file if new_bytes goes beyond current size
            # This allows LLM to create larger payloads from small seeds
            end_offset = offset + len(new_bytes)
            if end_offset > len(result):
                # Extend the file to accommodate new bytes
                result.extend(b'\x00' * (end_offset - len(result)))
            result[offset:offset + len(new_bytes)] = new_bytes
        
        elif op == "truncate":
            new_len = mut.get("new_len", 0)
            if new_len < 0:
                raise ValueError(f"truncate new_len {new_len} must be >= 0")
            if new_len < len(result):
                result = result[:new_len]
            elif new_len > len(result):
                # Extend with null bytes
                result.extend(b'\x00' * (new_len - len(result)))
        
        elif op == "repeat_range":
            offset = mut.get("offset", 0)
            length = mut.get("length", 0)
            times = mut.get("times", 1)
            
            if offset < 0 or offset >= len(result):
                raise ValueError(f"repeat_range offset {offset} out of range")
            if length <= 0:
                continue
            if times < 1:
                continue
            
            end = min(offset + length, len(result))
            chunk = bytes(result[offset:end])
            
            # Repeat the chunk
            for _ in range(times - 1):
                result.extend(chunk)
        
        elif op == "insert_repeated_bytes":
            offset = mut.get("offset", 0)
            hex_str = mut.get("hex", "").replace(" ", "")
            times = mut.get("times", 1)
            
            if offset < 0 or offset > len(result):
                raise ValueError(f"insert_repeated_bytes offset {offset} out of range [0, {len(result)}]")
            if times < 1:
                continue
            
            if not hex_str:
                continue
            if len(hex_str) % 2 != 0:
                raise ValueError(f"Invalid hex in insert_repeated_bytes: {hex_str} (odd length)")
            
            try:
                new_bytes = bytes.fromhex(hex_str)
            except ValueError as e:
                raise ValueError(f"Invalid hex in insert_repeated_bytes: {hex_str}") from e
                
            # Create the payload
            payload = new_bytes * times
            
            # Insert at offset using slice assignment (efficient)
            result[offset:offset] = payload
        
        elif op == "add_pax_header":
            # Smart mutation: Uses tarfile to rebuild the archive with a new PAX header
            key = mut.get("key", "SCHILY.xattr.user.overflow")
            length = mut.get("length", 1000)
            char = mut.get("value_char", "A")
            
            import tarfile
            import io
            
            # Create payload
            value = char * length
            pax_headers = {key: value}
            
            # Create new TAR in memory
            with io.BytesIO() as f_out:
                with tarfile.open(fileobj=f_out, mode="w") as tar:
                    # Create dummy info
                    info = tarfile.TarInfo("pax_payload")
                    info.size = 0
                    info.pax_headers = pax_headers
                    tar.addfile(info, io.BytesIO(b""))
                
                # Replace the ENTIRE seed with this new valid TAR
                # This intentionally discards previous mutations to ensure validity
                result = bytearray(new_tar_bytes)
        
        elif op == "add_json_nesting":
            # Smart mutation: Creates deeply nested JSON to trigger recursion limits
            # USES STRING MANIPULATION to avoid Python's json.dumps recursion limit
            layers = mut.get("layers", 100)
            key = mut.get("key", "a")
            value = mut.get("value", "leaf")
            
            # Sanitize inputs to ensure valid JSON components
            # (Basic check to avoid injection if LLM returns weird quotes)
            key = key.replace('"', '\\"')
            value = value.replace('"', '\\"')
            
            # Construct string: {"a":{"a": ... "value" ... }}
            # Each layer adds '{"key":' prefix and '}' suffix
            prefix = ('{"' + key + '":') * layers
            suffix = '}' * layers
            
            new_json_str = f'{prefix}"{value}"{suffix}'
            
            result = bytearray(new_json_str.encode("utf-8"))
            
        elif op == "add_json_field":
            # Smart mutation: Adds a field to the root JSON object
            key = mut.get("key", "payload")
            value_char = mut.get("value_char", "A")
            length = mut.get("length", 1000)
            
            import json
            
            try:
                # Try to load existing seed as JSON, or start fresh if invalid
                try:
                    data = json.loads(result.decode("utf-8", errors="ignore"))
                    if not isinstance(data, dict):
                        data = {}
                except:
                    data = {}
                
                # Add/Overwrite field
                data[key] = value_char * length
                
                new_json_bytes = json.dumps(data).encode("utf-8")
                result = bytearray(new_json_bytes)
            except Exception:
                # Fallback: just overwrite with a fresh JSON if something goes wrong
                data = {key: value_char * length}
                result = bytearray(json.dumps(data).encode("utf-8"))
        
        elif op == "pad_file":
            target_len = mut.get("target_len", 0)
            char = mut.get("char", "A")
            
            if target_len <= len(result):
                # If already larger, do nothing or truncate? Let's just do nothing to be safe, 
                # or maybe just ensure it's at least this size.
                pass 
            else:
                # Expand
                padding_len = target_len - len(result)
                try:
                    # Handle char as string or hex
                    pad_byte = char.encode('utf-8') if len(char) == 1 else bytes.fromhex(char)
                    pad_byte = pad_byte[:1] # Ensure single byte
                except:
                    pad_byte = b'A'
                
                result.extend(pad_byte * padding_len)
        
        else:
            raise ValueError(f"Unknown mutation operation: {op}")
        
        # Safety check: limit total size
        if len(result) > MAX_SEED_SIZE:
            raise ValueError(f"Seed size exceeded {MAX_SEED_SIZE} bytes after mutation")
    
    return bytes(result)
