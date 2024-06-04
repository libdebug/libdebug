from abc import ABC, abstractmethod, abstractproperty
from libdebug.state.debugging_context import provide_context
from enum import Enum

class Allocator(ABC):
    """The interface used to access an allocator"""

    def __init__(self):
        self.context = provide_context(self)

    @abstractproperty
    def name(self) -> str:
        """The name of the allocator"""

    @abstractproperty
    def free_list(self) -> dict[str, list[int]]:
        """Returns the free list"""

    @abstractproperty
    def allocated_memory(self) -> dict[str, list[int]]:
        """Returns the allocated memory area"""   

class AvailableAllocators(Enum):
    PTMALLOC2 = 1

