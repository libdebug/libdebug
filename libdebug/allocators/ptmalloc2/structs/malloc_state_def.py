import ctypes
from libdebug.allocators.ptmalloc2.structs import *

class c_malloc_state_2_27(ctypes.Structure):
    _fields_ = [
        ("mutex", ctypes.c_int32),
        ("flags", ctypes.c_int32),
        ("have_fastchunks", ctypes.c_int32),
        ("fastbinsY", c_pvoid * NFASTBINS),
        ("top", c_pvoid),
        ("last_remainder", c_pvoid),
        ("bins", c_pvoid * (NBINS * 2 - 2)),
        ("binmap", ctypes.c_int32 * BINMAPSIZE),
        ("next", c_pvoid),
        ("next_free", c_pvoid),
        ("attached_threads", c_size_t),
        ("system_mem", c_size_t),
        ("max_system_mem", c_size_t),
    ]