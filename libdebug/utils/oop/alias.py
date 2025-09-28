#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class AliasedProperty(property):
    """A property subclass that can store alias information.

    This class extends the built-in property to support the __aliases__ attribute
    that the AliasedClass metaclass expects for validation.
    """

    def __init__(
        self,
        fget: Callable | None = None,
        fset: Callable | None = None,
        fdel: Callable | None = None,
        doc: str | None = None,
    ) -> None:
        """Initialize an aliased property.

        Args:
            fget: The getter function
            fset: The setter function
            fdel: The deleter function
            doc: The docstring
        """
        super().__init__(fget, fset, fdel, doc)
        self.__aliases__: tuple[str, ...] = ()


def alias(*alias_names: str) -> Callable:
    """Decorator to mark a function or method with alias names.

    Args:
        *alias_names: One or more alias names to associate with the decorated object.
    """

    def decorator(obj: Callable) -> Callable:
        if not alias_names:
            raise ValueError("alias(): at least one alias name is required")
        obj.__aliases__ = (*getattr(obj, "__aliases__", ()), *alias_names)
        return obj

    return decorator


def aliased_property(*alias_names: str) -> Callable:
    """Decorator to create a property with alias names.

    This decorator creates an AliasedProperty that can store alias information
    for use with the AliasedClass metaclass.

    Args:
        *alias_names: One or more alias names for the property.
    """
    if not alias_names:
        raise ValueError("aliased_property(): at least one alias name is required")

    def decorator(func: Callable) -> AliasedProperty:
        """Create an AliasedProperty with the specified aliases."""
        prop = AliasedProperty(func, doc=func.__doc__)
        prop.__aliases__ = alias_names
        return prop

    return decorator
