import struct

def u64(value):
    return struct.unpack("<Q", value)[0]

def u32(value):
    return struct.unpack("<I", value)[0]
