#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025  Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


class ArgumentList(list[str]):
    """A list that behaves like a normal list of strings but provides callbacks for modifications.

    Can be configured to always maintain at least one element.

    This class inherits from list and overrides all methods that can modify the list
    to provide before/after callbacks and optional protection against complete clearing.
    """

    def __init__(self: Self, iterable: Iterable[str] | None = None) -> None:
        """
        Initialize the trackable list.

        Args:
            iterable: Optional initial items for the list
        """
        # Validate items before calling super().__init__()
        if iterable is not None:
            if not hasattr(iterable, "__iter__"):
                raise TypeError(f"Expected an iterable, got {type(iterable).__name__}")

            validated_items = []
            for i, item in enumerate(iterable):
                if not isinstance(item, str):
                    raise TypeError(
                        f"ArgumentList can only contain strings, got {type(item).__name__} at index {i}: {item!r}",
                    )
                validated_items.append(item)
            super().__init__(validated_items)
        else:
            super().__init__()

        self._before_callback: Callable[[list[str]], None] | None = None
        self._after_callback: Callable[[list[str]], None] | None = None
        self._prevent_empty: bool = False

    def set_callbacks(
        self,
        before_callback: Callable[[list[str]], None] | None = None,
        after_callback: Callable[[list[str]], None] | None = None,
    ) -> None:
        """
        Set the callbacks that will be called before and after list modifications.

        Args:
            before_callback: Function called before modification with a copy of the current list state
            after_callback: Function called after modification with a copy of the new list state
        """
        self._before_callback = before_callback
        self._after_callback = after_callback

    @property
    def prevent_empty(self) -> bool:
        """Get the current prevent_empty setting."""
        return self._prevent_empty

    @prevent_empty.setter
    def prevent_empty(self, value: bool) -> None:
        """Set the prevent_empty setting, with validation."""
        if value and len(self) == 0:
            raise ValueError("Cannot enable prevent_empty on an already empty list")
        self._prevent_empty = value

    def _call_before_callback(self) -> None:
        """Call the before callback if set with current list state."""
        if self._before_callback:
            self._before_callback(list(self))  # Pass a copy of current state

    def _call_after_callback(self) -> None:
        """Call the after callback if set with current list state."""
        if self._after_callback:
            self._after_callback(list(self))  # Pass a copy of current state

    def _validate_string(self, item: object) -> str:
        """Validate that an item is a string and return it."""
        if not isinstance(item, str):
            raise TypeError(f"ArgumentList can only contain strings, got {type(item).__name__}: {item!r}")
        return item

    def _validate_string_iterable(self, iterable: object) -> list[str]:
        """Validate that all items in an iterable are strings."""
        if not hasattr(iterable, "__iter__"):
            raise TypeError(f"Expected an iterable, got {type(iterable).__name__}")

        validated_items = []
        for i, item in enumerate(iterable):
            if not isinstance(item, str):
                raise TypeError(
                    f"ArgumentList can only contain strings, got {type(item).__name__} at index {i}: {item!r}",
                )
            validated_items.append(item)
        return validated_items

    def append(self, item: str) -> None:
        """Append an item to the list."""
        validated_item = self._validate_string(item)
        self._call_before_callback()
        super().append(validated_item)
        self._call_after_callback()

    def extend(self, iterable: Iterable[str]) -> None:
        """Extend the list with items from an iterable."""
        validated_items = self._validate_string_iterable(iterable)
        self._call_before_callback()
        super().extend(validated_items)
        self._call_after_callback()

    def insert(self, index: int, item: str) -> None:
        """Insert an item at the specified index."""
        validated_item = self._validate_string(item)
        self._call_before_callback()
        super().insert(index, validated_item)
        self._call_after_callback()

    def remove(self, item: str) -> None:
        """Remove the first occurrence of an item."""
        self._call_before_callback()
        if self._prevent_empty and len(self) <= 1 and item in self:
            raise ValueError("Argument list must maintain at least one element")
        super().remove(item)
        self._call_after_callback()

    def pop(self, index: int = -1) -> str:
        """Remove and return an item at the specified index (default last)."""
        self._call_before_callback()
        if self._prevent_empty and len(self) <= 1:
            raise ValueError("Argument list must maintain at least one element")
        result = super().pop(index)
        self._call_after_callback()
        return result

    def clear(self) -> None:
        """Remove all items from the list."""
        self._call_before_callback()
        if self._prevent_empty and len(self) > 0:
            raise ValueError("Argument list must maintain at least one element")
        super().clear()
        self._call_after_callback()

    def reverse(self) -> None:
        """Reverse the list in place."""
        self._call_before_callback()
        super().reverse()
        self._call_after_callback()

    def sort(self, *, key: Callable[[str], object] | None = None, reverse: bool = False) -> None:
        """Sort the list in place."""
        self._call_before_callback()
        super().sort(key=key, reverse=reverse)
        self._call_after_callback()

    def __setitem__(self, index: int | slice, value: str) -> None:
        """Set an item or slice of items."""
        if isinstance(index, slice):
            # For slice assignment, value should be an iterable
            validated_value = self._validate_string_iterable(value)
        else:
            # For single item assignment, value should be a string
            validated_value = self._validate_string(value)
        self._call_before_callback()
        super().__setitem__(index, validated_value)
        self._call_after_callback()

    def __delitem__(self, index: int | slice) -> None:
        """Delete an item or slice of items."""
        self._call_before_callback()
        if self._prevent_empty:
            if isinstance(index, slice):
                start, stop, step = index.indices(len(self))
                items_to_delete = max(0, stop - start) if step == 1 else len(range(start, stop, step))
                if len(self) <= items_to_delete:
                    raise ValueError("Argument list must maintain at least one element")
            elif len(self) <= 1:
                raise ValueError("Argument list must maintain at least one element")
        super().__delitem__(index)
        self._call_after_callback()

    def __iadd__(self, other: Iterable[str]) -> Self:
        """Implement += operator."""
        validated_other = self._validate_string_iterable(other)
        self._call_before_callback()
        super().__iadd__(validated_other)
        self._call_after_callback()
        return self

    def __imul__(self, other: int) -> Self:
        """Implement *= operator."""
        self._call_before_callback()
        super().__imul__(other)
        self._call_after_callback()
        return self
