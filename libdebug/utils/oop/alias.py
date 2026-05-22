#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generic, ParamSpec, TypeVar, overload

if TYPE_CHECKING:
    from collections.abc import Callable

P = ParamSpec("P")
T = TypeVar("T")


class AliasedProperty(property, Generic[T]):
    """A property subclass that can store alias information.

    This class extends the built-in property to support the __aliases__ attribute
    that the AliasedClass metaclass expects for validation.
    """

    def __init__(
        self,
        fget: Callable[[Any], T] | None = None,
        fset: Callable[[Any, T], None] | None = None,
        fdel: Callable[[Any], None] | None = None,
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

    if TYPE_CHECKING:
        @overload
        def __get__(self, instance: None, owner: type | None = ..., /) -> AliasedProperty[T]: ...
        @overload
        def __get__(self, instance: object, owner: type | None = ..., /) -> T: ...
        def __get__(self, instance: object | None, owner: type | None = ..., /) -> AliasedProperty[T] | T:
            """Descriptor accessor; implementation inherited from `property`."""
            ...


def check_alias(*alias_names: str) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorator to register alternate names for a function or method.

    This helper exists solely for `alias_test`, where we verify that alias
    names expose the same docstring, arguments, and typing info as the
    original callable. Applying this decorator only stores metadata and does
    not create an alias on its own.

    Args:
        *alias_names: One or more alias names to associate with the decorated object.
    """

    def decorator(obj: Callable[P, T]) -> Callable[P, T]:
        if not alias_names:
            raise ValueError("alias(): at least one alias name is required")
        obj.__aliases__ = (*getattr(obj, "__aliases__", ()), *alias_names)
        return obj

    return decorator


def check_aliased_property(*alias_names: str) -> Callable[[Callable[..., T]], AliasedProperty[T]]:
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

    def decorator(func: Callable[..., T]) -> AliasedProperty[T]:
        """Create an AliasedProperty with the specified aliases."""
        prop: AliasedProperty[T] = AliasedProperty(func, doc=func.__doc__)
        prop.__aliases__ = alias_names
        return prop

    return decorator
