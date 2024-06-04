from __future__ import annotations

from libdebug.allocators.ptmalloc2.arena import Arena
from libdebug.allocators.allocator import Allocator
from libdebug.state.debugging_context import context_extend_from

class Heap(Allocator):
    """Implementation of ptmalloc2 heap allocator"""
    def __init__(self: Heap) -> None:
        super().__init__()
        self._main_arena : Arena | None = None

    def name(self) -> str:
        return "ptmalloc2"

    def free_list(self) -> dict[str, list[int]]:
        return []
    
    def allocated_memory(self) -> dict[str, list[int]]:
        raise NotImplementedError("Not implemented yet")
    
    @property
    def main_arena(self) -> Arena:
        from libdebug import libcontext
        if self._main_arena is None:            
            # Initialize the main arena
            with libcontext.tmp(sym_lvl = 5):
                main_arena_address = self.context.resolve_symbol("main_arena")
            
            with context_extend_from(self):
                self._main_arena = Arena(main_arena_address)
        
        return self._main_arena

    @property
    def fastbins(self) -> dict[int, list[int]]:
        return self.main_arena.fastbins




