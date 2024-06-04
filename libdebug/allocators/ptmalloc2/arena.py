from libdebug.state.debugging_context import debugging_context
from libdebug.allocators.ptmalloc2.structs.malloc_state_def import c_malloc_state_2_27
import ctypes

"""An arena of the heap"""
class Arena:
    def __init__(self, address):
        """Initialize the arena object found at address"""
        self.context = debugging_context()

        self.context.interrupt()
        # Get the correct struct type to read
        # TODO: make this libc independent
        struct_def : ctypes.Structure = c_malloc_state_2_27

        # Read from memory the main arena
        arena_bytes = self.context.memory.read(address, ctypes.sizeof(struct_def))
        arena_struct = struct_def.from_buffer_copy(arena_bytes)

        self.mutex = arena_struct.mutex
        self.flags = arena_struct.flags
        
        # To read 
        self.fastbinsY = arena_struct.fastbinsY

        self.top = arena_struct.top
        self.last_remainder = arena_struct.last_remainder
        self.bins = arena_struct.bins
        self.binmap = arena_struct.binmap
        self.next = arena_struct.next
        self.next_free = arena_struct.next_free
        self.attached_threads = arena_struct.attached_threads
        self.system_mem = arena_struct.system_mem
        self.max_system_mem = arena_struct.max_system_mem

    

