import ctypes
# TODO: make this architecture independent. For now, works only on 64-bits archs.

c_pvoid = ctypes.c_uint64 
c_size_t = ctypes.c_uint64
NFASTBINS = 10
BINMAPSIZE = 4
NBINS = 128