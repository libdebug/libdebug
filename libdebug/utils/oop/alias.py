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


def check_alias(*alias_names: str) -> Callable:
    """Decorator to register alternate names for a function or method.

    This helper exists solely for `alias_test`, where we verify that alias
    names expose the same docstring, arguments, and typing info as the
    original callable. Applying this decorator only stores metadata and does
    not create an alias on its own.

    Args:
        *alias_names: One or more alias names to associate with the decorated object.
    """

    def decorator(obj: Callable) -> Callable:
        if not alias_names:
            raise ValueError("alias(): at least one alias name is required")
        obj.__aliases__ = (*getattr(obj, "__aliases__", ()), *alias_names)
        return obj

    return decorator


def check_aliased_property(*alias_names: str) -> Callable:
    """Decorator to record alternate names for a property.

    It builds an AliasedProperty containing those aliases solely for
    `alias_test`, which confirms that every alias shares the same docstring,
    arguments, and typing details as the original property implementation.
    Like `check_alias`, it merely tags metadata and does not create aliases by
    itself.

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
