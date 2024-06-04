from __future__ import annotations

from abc import ABC, abstractmethod
from libdebug.state.debugging_context import provide_context
from enum import Enum

class Allocator(ABC):
    """The interface used to access an allocator"""

    def __init__(self) -> Allocator:
        self.context = provide_context(self)

    @property
    @abstractmethod
    def name(self) -> str:
        """The name of the allocator"""

    @property
    @abstractmethod
    def free_list(self) -> dict[str, list[int]]:
        """Returns the free list"""

    @property
    @abstractmethod
    def allocated_memory(self) -> dict[str, list[int]]:
        """Returns the allocated memory area"""   

class AvailableAllocators(Enum):
    PTMALLOC2 = 1

