from __future__ import annotations

from libdebug.state.debugging_context import debugging_context, DebuggingContext
from libdebug.allocators.ptmalloc2.structs.malloc_state_def import c_malloc_state_2_27, fastbinsY_t
import ctypes

class Arena:
    def __init__(self, address) -> Arena:
        """Initializa an arena object with the address of the corresponding malloc_state struct in memory"""
        self.address : int = address
        self.context : DebuggingContext = debugging_context()

        # Stop the program to read the memory
        self.context.interrupt()

        # Get the correct struct type to read
        # TODO: make this libc independent
        self.struct_def : ctypes.Structure = c_malloc_state_2_27  

    @property
    def fastbins(self) -> dict[int, int]:
        """Returns the head of each fastbin of the arena"""
        # TODO: return the list of chunks inside the bin, and not only the head        
        # Read the fastbins head from memory
        bins_pointers = self.context.memory.read(
                            address = self.address + self.struct_def.fastbinsY.offset,
                            size = ctypes.sizeof(fastbinsY_t)
                            )
        
        # Interpret the result as addresses
        bins_pointers = fastbinsY_t.from_buffer_copy(bins_pointers)

        # Format the bins head
        f = {0x10 + i  * 8: int(x) for i, x in enumerate(bins_pointers)}   
        return f   







    

