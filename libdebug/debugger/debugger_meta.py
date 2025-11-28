#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import inspect
from typing import Any

from libdebug.debugger.mixins.base import EngineBoundMixin
from libdebug.liblog import liblog


class DebuggerMeta(type):
    """Metaclass that warns on method collisions across mixins."""

    @staticmethod
    def _iter_declared_attributes(base_cls: type) -> set[str]:
        attrs: set[str] = set()
        for name, value in base_cls.__dict__.items():
            if name.startswith("__"):
                continue
            if inspect.isfunction(value) or isinstance(value, property | staticmethod | classmethod):
                attrs.add(name)
        return attrs

    def __new__(cls, name: str, bases: tuple[type, ...], namespace: dict[str, Any]) -> type:
        """Build the Debugger subclass and warn on mixin collisions."""
        new_cls: type = super().__new__(cls, name, bases, namespace)
        collisions: dict[str, list[str]] = {}
        for base in new_cls.mro()[1:]:  # skip cls itself
            if base is object or not issubclass(base, EngineBoundMixin):
                continue
            for attr in DebuggerMeta._iter_declared_attributes(base):
                collisions.setdefault(attr, []).append(base.__name__)

        for attr, providers in collisions.items():
            unique_providers = list(dict.fromkeys(providers))
            if len(unique_providers) > 1:
                aliases: list[str] = []
                for provider in unique_providers:
                    provider_cls = next((b for b in new_cls.mro() if b.__name__ == provider), None)
                    if provider_cls is None:
                        continue
                    source = provider_cls.__dict__.get(attr)
                    alias_name = f"{provider}__{attr}"
                    if source is not None and not hasattr(new_cls, alias_name):
                        setattr(new_cls, alias_name, source)
                        aliases.append(alias_name)
                liblog.warning(
                    "Debugger mixin method collision on '%s': %s. MRO will use the left-most definition. "
                    "Aliases added (use these to call specific implementations): %s",
                    attr,
                    unique_providers,
                    aliases if aliases else "none",
                )
        return new_cls
