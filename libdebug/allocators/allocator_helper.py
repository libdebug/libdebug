from libdebug.allocators.allocator import AvailableAllocators
from libdebug.allocators.allocator import Allocator
from libdebug.allocators.ptmalloc2.heap import Heap 

def provide_allocator_interface(
    allocator: AvailableAllocators = AvailableAllocators.PTMALLOC2,
) -> Allocator:
    """Returns an instance of the debugging interface to be used by the `_InternalDebugger` class."""
    match allocator:
        case AvailableAllocators.PTMALLOC2:
            return Heap()
        case _:
            raise NotImplementedError(f"Allocator {allocator} not available.")
