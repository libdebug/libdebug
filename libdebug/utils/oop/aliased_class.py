#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from inspect import isdatadescriptor, isfunction, ismethod, signature
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


class AliasedClass(type):
    """Metaclass that ensures aliased methods and properties have identical signatures and docstrings.

    This metaclass validates that methods and properties marked with __aliases__ have
    corresponding aliases in the class with identical signatures and docstrings.
    It's used to enforce consistency between aliased members during class creation.
    """

    def _validate_docstring(
        cls,
        attr_name: str,
        original_docstring: str,
        alias_docstring: str,
        is_property: bool = False,
    ) -> None:
        """Validate that two docstrings are similar.

        The alias docstring is expected to have a line declaring it as an alias,
        but otherwise should match the original docstring.

        Args:
            attr_name: Name of the original attribute
            original_docstring: The original docstring to validate against
            alias_docstring: The alias docstring to validate
            is_property: Whether the attribute is a property (affects wording in alias line)

        Raises:
            TypeError: If the docstrings do not match
        """
        constructed_alias_docstring = (
            f"Alias for the `{attr_name}` {'property' if is_property else 'method'}.\n\n{original_docstring}"
        )

        if constructed_alias_docstring == alias_docstring:
            return

        # The alias docstring might contain an additional newline at the end
        if constructed_alias_docstring + "\n" == alias_docstring:
            return

        raise TypeError(f"Docstring mismatch between '{attr_name}' and its alias")

    def _validate_function_alias(
        cls,
        original: Callable,
        alias: Callable,
        attr_name: str,
        alias_name: str,
    ) -> None:
        """Validate that a function alias matches the original function.

        Args:
            original: The original function or method to validate against
            alias: The alias function or method to validate
            attr_name: Name of the original attribute
            alias_name: Name of the alias attribute

        Raises:
            TypeError: If the alias is not a function/method, or if signatures
                      or docstrings don't match between original and alias
        """
        if not (isfunction(alias) or ismethod(alias)):
            raise TypeError(f"Alias '{alias_name}' of '{attr_name}' must be a function or method")
        if signature(original) != signature(alias):
            raise TypeError(f"Signature mismatch between '{attr_name}' and its alias '{alias_name}'")
        cls._validate_docstring(cls, attr_name, original.__doc__, alias.__doc__)

    def _validate_property_alias(
        cls,
        original: object,
        alias: object,
        attr_name: str,
        alias_name: str,
    ) -> None:
        """Validate that a property alias matches the original property.

        Args:
            original: The original property descriptor to validate against
            alias: The alias property descriptor to validate
            attr_name: Name of the original attribute
            alias_name: Name of the alias attribute

        Raises:
            TypeError: If the alias is not a data descriptor, or if signatures
                      or docstrings don't match between original and alias
                      for any of the property methods (fget, fset, fdel)
        """
        if not isdatadescriptor(alias):
            raise TypeError(f"Alias '{alias_name}' of '{attr_name}' must be a data descriptor")
        # For properties, we check the fget, fset, and fdel methods
        for method in ("fget", "fset", "fdel"):
            orig_method = getattr(original, method)
            alias_method = getattr(alias, method)
            # fset and fdel can be None if not defined, so we only validate if both are present
            if orig_method and alias_method:
                if signature(orig_method) != signature(alias_method):
                    raise TypeError(
                        f"Signature mismatch in {method} between '{attr_name}' and its alias '{alias_name}'",
                    )
                cls._validate_docstring(cls, attr_name, orig_method.__doc__, alias_method.__doc__, is_property=True)
            elif orig_method != alias_method:
                raise TypeError(
                    f"Method '{method}' presence mismatch between '{attr_name}' and its alias '{alias_name}'",
                )

    def __new__(
        cls,
        name: str,
        bases: tuple[type, ...],
        namespace: dict[str, object],
    ) -> type:
        """Create a new class and validate all aliased methods and properties.

        This method is called when a new class is created with this metaclass.
        It validates that all attributes marked with __aliases__ have corresponding
        aliases with matching signatures and docstrings.
        """
        new_cls = super().__new__(cls, name, bases, namespace)

        # We validate all aliased attributes in the class namespace
        # and in the bases (to support inheritance)
        for base in bases:
            for attr_name, attr_value in base.__dict__.items():
                if hasattr(attr_value, "__aliases__"):
                    for alias_name in attr_value.__aliases__:
                        if hasattr(new_cls, alias_name):
                            alias_value = getattr(new_cls, alias_name)
                            if isfunction(attr_value) or ismethod(attr_value):
                                cls._validate_function_alias(cls, attr_value, alias_value, attr_name, alias_name)
                            elif isdatadescriptor(attr_value):
                                cls._validate_property_alias(cls, attr_value, alias_value, attr_name, alias_name)
                            else:
                                raise TypeError(
                                    f"Alias '{alias_name}' of '{attr_name}' must be a function, method, or data descriptor",
                                )
                        else:
                            raise AttributeError(
                                f"Alias '{alias_name}' for '{attr_name}' does not exist in class '{name}'",
                            )
        return new_cls
