import ctypes
from libdebug.allocators.ptmalloc2.structs import *

fastbinsY_t = c_pvoid * NFASTBINS
class c_malloc_state_2_27(ctypes.Structure):
    _fields_ = [
        ("mutex", ctypes.c_int32),
        ("flags", ctypes.c_int32),
        ("have_fastchunks", ctypes.c_int32),
        ("fastbinsY", fastbinsY_t),
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