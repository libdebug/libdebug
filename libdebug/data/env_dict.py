#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025  Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping


class EnvDict(dict[str, str]):
    """A dict that behaves like a normal dict of strings but provides a callback for modifications.

    This class inherits from dict and overrides all methods that can modify the dict
    to provide an update callback for tracking changes.
    """

    def __init__(
        self: EnvDict,
        mapping_or_iterable: Mapping[str, str] | Iterable | None = None,
        **kwargs: str,
    ) -> None:
        """
        Initialize the trackable dict.

        Args:
            mapping_or_iterable: Optional mapping or iterable of key-value pairs
            **kwargs: Keyword arguments for initial items
        """
        # Validate items before calling super().__init__()
        if mapping_or_iterable is not None or kwargs:
            temp_dict = dict(mapping_or_iterable, **kwargs) if mapping_or_iterable is not None else dict(**kwargs)
            validated_dict = EnvDict._validate_string_mapping(temp_dict)
            super().__init__(validated_dict)
        else:
            super().__init__()

        self._update_callback: Callable[[], None] | None = None

    def set_callback(
        self: EnvDict,
        update_callback: Callable[[], None] | None = None,
    ) -> None:
        """
        Set the callback that will be called after dict modifications.

        Args:
            update_callback: Function called after modification
        """
        self._update_callback = update_callback

    def _call_update_callback(self: EnvDict) -> None:
        """Call the update callback if set."""
        if self._update_callback:
            self._update_callback()

    def _validate_string_key(self: EnvDict, key: object) -> str:
        """Validate that a key is a string and return it."""
        if not isinstance(key, str):
            raise TypeError(f"EnvDict keys must be strings, got {type(key).__name__}: {key!r}")
        return key

    def _validate_string_value(self: EnvDict, value: object) -> str:
        """Validate that a value is a string and return it."""
        if not isinstance(value, str):
            raise TypeError(f"EnvDict values must be strings, got {type(value).__name__}: {value!r}")
        return value

    @staticmethod
    def _validate_string_mapping(mapping: Mapping[object, object]) -> dict[str, str]:
        """Validate that all keys and values in a mapping are strings."""
        validated_dict = {}
        for key, value in mapping.items():
            if not isinstance(key, str):
                raise TypeError(f"EnvDict keys must be strings, got {type(key).__name__}: {key!r}")
            if not isinstance(value, str):
                raise TypeError(f"EnvDict values must be strings, got {type(value).__name__}: {value!r}")
            validated_dict[key] = value
        return validated_dict

    def __setitem__(self: EnvDict, key: str, value: str) -> None:
        """Set an item in the dict."""
        validated_key = self._validate_string_key(key)
        validated_value = self._validate_string_value(value)
        self._call_update_callback()
        super().__setitem__(validated_key, validated_value)

    def __delitem__(self: EnvDict, key: str) -> None:
        """Delete an item from the dict."""
        self._call_update_callback()
        super().__delitem__(key)

    def clear(self: EnvDict) -> None:
        """Remove all items from the dict."""
        self._call_update_callback()
        super().clear()

    def pop(self: EnvDict, key: str, default: str | None = None) -> str:
        """Remove specified key and return the corresponding value."""
        self._call_update_callback()
        if default is None:
            result = super().pop(key)
        else:
            validated_default = self._validate_string_value(default)
            result = super().pop(key, validated_default)
        return result

    def popitem(self: EnvDict) -> tuple[str, str]:
        """Remove and return an arbitrary (key, value) pair from the dict."""
        self._call_update_callback()
        return super().popitem()

    def setdefault(self: EnvDict, key: str, default: str | None = None) -> str:
        """Insert key with a value of default if key is not in the dict."""
        validated_key = self._validate_string_key(key)
        validated_default = self._validate_string_value(default) if default is not None else ""

        self._call_update_callback()
        return super().setdefault(validated_key, validated_default)

    def update(
        self: EnvDict,
        mapping_or_iterable: Mapping[str, str] | None = None,
        **kwargs: str,
    ) -> None:
        """Update the dict with the key/value pairs from other, overwriting existing keys."""
        # Validate the input before making any changes
        validated_dict = {}

        if mapping_or_iterable is not None:
            if hasattr(mapping_or_iterable, "keys"):
                validated_dict = EnvDict._validate_string_mapping(mapping_or_iterable)
            else:
                # Handle iterable of key-value pairs
                for key, value in mapping_or_iterable:
                    validated_key = self._validate_string_key(key)
                    validated_value = self._validate_string_value(value)
                    validated_dict[validated_key] = validated_value

        # Validate kwargs
        if kwargs:
            validated_kwargs = EnvDict._validate_string_mapping(kwargs)
            validated_dict.update(validated_kwargs)

        self._call_update_callback()
        super().update(validated_dict)

    def __ior__(self: EnvDict, other: Mapping[str, str]) -> EnvDict:
        """Implement |= operator."""
        validated_other = EnvDict._validate_string_mapping(other)
        self._call_update_callback()
        super().__ior__(validated_other)
        return self
