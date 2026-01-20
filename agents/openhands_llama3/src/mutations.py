"""Seed mutation operations for fuzzing."""
from __future__ import annotations
from typing import List, Dict

MAX_SEED_SIZE = 1024 * 1024  # 1MB limit


def apply_mutations(seed_bytes: bytes, mutations: List[Dict]) -> bytes:
    """
    Apply a list of mutation operations to seed bytes.
    
    Supported operations:
    - append_bytes: {"op": "append_bytes", "hex": "deadbeef"}
    - flip_bit: {"op": "flip_bit", "offset": 123, "bit": 5}
    - overwrite_range: {"op": "overwrite_range", "offset": 10, "hex": "cafebabe"}
    - truncate: {"op": "truncate", "new_len": 200}
    - repeat_range: {"op": "repeat_range", "offset": 20, "length": 40, "times": 3}
    """
    result = bytearray(seed_bytes)
    
    for mut in mutations:
        op = mut.get("op", "")
        
        if op == "append_bytes":
            hex_str = mut.get("hex", "").replace(" ", "")
            if not hex_str:
                continue
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
            try:
                new_bytes = bytes.fromhex(hex_str)
            except ValueError as e:
                raise ValueError(f"Invalid hex in overwrite_range: {hex_str}") from e
            
            if offset < 0 or offset >= len(result):
                raise ValueError(f"overwrite_range offset {offset} out of range")
            
            end = min(offset + len(new_bytes), len(result))
            result[offset:end] = new_bytes[:end-offset]
        
        elif op == "truncate":
            new_len = mut.get("new_len", 0)
            if new_len < 0:
                raise ValueError(f"truncate new_len {new_len} must be >= 0")
            if new_len < len(result):
                result = result[:new_len]
        
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
        
        else:
            raise ValueError(f"Unknown mutation operation: {op}")
        
        # Safety check: limit total size
        if len(result) > MAX_SEED_SIZE:
            raise ValueError(f"Seed size exceeded {MAX_SEED_SIZE} bytes after mutation")
    
    return bytes(result)
