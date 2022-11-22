import struct

def u64(value):
    return struct.unpack("<Q", value)[0]

def u32(value):
    return struct.unpack("<I", value)[0]

def inverse_mapping(f):
    return f.__class__(map(reversed, f.items()))