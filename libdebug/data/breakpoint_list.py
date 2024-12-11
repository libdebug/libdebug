#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.data.breakpoint import Breakpoint

if TYPE_CHECKING:
    from collections.abc import Callable

    from libdebug.state.thread_context import ThreadContext


class BreakpointList(list):
    """A list of breakpoints installed at the same address in the target process.

    Attributes:
        address (int): The address of the breakpoints installed in the target process.
        symbol (str): The symbol, if available, of the breakpoints installed in the target process.
        hit_count (int): The sum of the hit counts of all the breakpoints inside the BreakpointList.
        callback list[Callable[[ThreadContext, Breakpoint], None]]: The list of callbacks defined by the user to execute when the breakpoints are hit.
        enabled (bool): Whether at least one of the breakpoints is enabled or not.
    """

    address: int = 0
    symbol: str = ""

    def __init__(self: BreakpointList, breakpoints: list[Breakpoint], address: int, symbol: str) -> None:
        """Initializes the BreakpointList."""
        self.address = address
        self.symbol = symbol
        super().__init__(breakpoints)

    @property
    def hit_count(self: BreakpointList) -> int:
        """Returns the sum of the hit counts of all the breakpoints inside the BreakpointList."""
        return sum(bp.hit_count for bp in self)

    @property
    def callback(self: BreakpointList) -> list[Callable[[ThreadContext, Breakpoint], None]]:
        """Returns the list of callbacks defined by the user to execute when the breakpoints are hit."""
        return [bp.callback for bp in self]

    @property
    def enabled(self: BreakpointList) -> bool:
        """Returns whether at least one of the breakpoints is enabled or not."""
        return any(bp.enabled for bp in self)

    def filter(self: BreakpointList, **kwargs: dict[str, object]) -> BreakpointList:
        """Filters the breakpoints according to the specified Breakpoint attributes.

        Args:
            **kwargs: The arguments to filter the breakpoints. It can be any Breakpoint attribute.

        Returns:
            BreakpointList[Breakpoint]: The list of breakpoints installed in the specified thread and/or with the specified condition.
        """
        if not kwargs:
            return self

        filtered_breakpoints = self
        for key, value in kwargs.items():
            if key not in Breakpoint.__annotations__:
                raise ValueError(f"Invalid attribute: {key} is not a valid Breakpoint attribute")
            if key == "thread_id":
                filtered_breakpoints = [bp for bp in filtered_breakpoints if bp.thread_id in (value, -1)]
            else:
                filtered_breakpoints = [bp for bp in filtered_breakpoints if getattr(bp, key) == value]

        return BreakpointList(filtered_breakpoints, self.address, self.symbol)

    def __hash__(self) -> int:
        """Return the hash of the symbol list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the symbol list is equal to another object."""
        return super().__eq__(other)

    def __repr__(self: BreakpointList) -> str:
        """Returns the string representation of the BreakpointList without the default factory."""
        return f"BreakpointList({super().__repr__()})"
