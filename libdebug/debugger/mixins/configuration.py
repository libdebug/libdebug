#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.argument_list import ArgumentList
from libdebug.data.env_dict import EnvDict
from libdebug.debugger.mixins.base import EngineBoundMixin
from libdebug.utils.arch_mappings import map_arch
from libdebug.utils.elf_utils import elf_architecture, resolve_argv_path
from libdebug.utils.signal_utils import (
    get_all_signal_numbers,
    resolve_signal_name,
    resolve_signal_number,
)


class ConfigurationMixin(EngineBoundMixin):
    """Configuration and setup helpers for the debugger."""

    _previous_argv: list[str]
    """A copy of the previous argv state, used internally to detect changes to argv[0]."""

    def __init__(self: ConfigurationMixin) -> None:
        """Install argv/env callbacks after the engine is wired."""
        super().__init__()
        self._configure_argument_list(self._internal_debugger.argv)
        self._configure_env_dict()

    @property
    def arch(self: ConfigurationMixin) -> str:
        """Get the architecture of the process."""
        return self._internal_debugger.arch

    @arch.setter
    def arch(self: ConfigurationMixin, value: str) -> None:
        """Set the architecture of the process."""
        self._internal_debugger.arch = map_arch(value)

    def _configure_argument_list(self: ConfigurationMixin, argv: ArgumentList) -> None:
        """Sets up the ArgumentList with the before/after callbacks, and freezes argv[0] if needed."""
        # If the user has not specified a different path, and argv is not empty, we should freeze argv[0]
        if not self._internal_debugger._has_path_different_from_argv0 and argv and argv[0]:
            argv.prevent_empty = True
        else:
            argv.prevent_empty = False

        # We register a _before_callback that stores a copy of the current argv state
        def _before_callback(_: list[str]) -> None:
            """Store a copy of the current argv state."""
            # Changing argv is not allowed while the process is being debugged.
            if self._internal_debugger.is_debugging:
                raise RuntimeError("Cannot change argv while the process is running. Please kill it first.")

            self._previous_argv = list(self._internal_debugger.argv) if self._internal_debugger.argv else []

        # The _after callback should check if argv[0] has changed and update the path accordingly
        def _after_callback(new_argv: list[str]) -> None:
            """An after callback that updates the path if argv[0] has changed."""
            if not hasattr(self, "_previous_argv"):
                raise RuntimeError("The _previous_argv attribute is not set. This should not happen.")

            try:
                if (
                    not self._internal_debugger._has_path_different_from_argv0
                    and new_argv
                    and new_argv[0] != self._previous_argv[0]
                ):
                    self._internal_debugger.clear_all_caches()
                    # Changing path can also change the architecture, so we need to update it
                    resolved_path = resolve_argv_path(new_argv[0])
                    self.arch = elf_architecture(resolved_path)
                    self._internal_debugger.path = resolved_path
            except Exception:
                # We revert to the previous argv state if something goes wrong
                self._internal_debugger.argv = ArgumentList(self._previous_argv)
                raise

        # Set the callbacks on the ArgumentList
        argv.set_callbacks(_before_callback, _after_callback)

    @property
    def argv(self: ConfigurationMixin) -> ArgumentList:
        """The command line arguments of the debugged process."""
        self._internal_debugger._ensure_process_stopped()
        return self._internal_debugger.argv

    @argv.setter
    def argv(self: ConfigurationMixin, value: str | list[str] | ArgumentList) -> None:
        """Set the command line arguments of the debugged process."""
        self._internal_debugger._ensure_process_stopped()

        # Changing argv is not allowed while the process is being debugged.
        if self._internal_debugger.is_debugging:
            raise RuntimeError("Cannot change argv while the process is running. Please kill it first.")

        if not isinstance(value, str | list | ArgumentList):
            raise TypeError("argv must be a string or a list of strings")
        if isinstance(value, str):
            value = ArgumentList([value])
        elif isinstance(value, list):
            value = ArgumentList(value)

        # We need to install on the ArgumentList the proper callbacks
        self._configure_argument_list(value)

        # We have to check whether argv[0] has changed
        # if so, we should invalidate everything and resolve the path again
        # but that should be done only if path depended on argv[0]
        if (
            not self._internal_debugger._has_path_different_from_argv0
            and self._internal_debugger.argv
            and value[0] != self._internal_debugger.argv[0]
        ):
            self._internal_debugger.clear_all_caches()
            # Changing path can also change the architecture, so we need to update it
            resolved_path = resolve_argv_path(value[0])
            self.arch = elf_architecture(resolved_path)
            self._internal_debugger.path = resolved_path

        self._internal_debugger.argv = value

    def _configure_env_dict(self: ConfigurationMixin) -> None:
        """Sets up the EnvDict with the before callback."""

        # We register a _before_callback that ensure that the process
        # is not being debugged when the environment is changed
        def _before_callback() -> None:
            """Ensure that the process is not being debugged when the environment is changed."""
            # Changing env is not allowed while the process is being debugged.
            if self._internal_debugger.is_debugging:
                raise RuntimeError("Cannot change env while the process is running. Please kill it first.")

        if self._internal_debugger.env is not None:
            # If the env is already set, we just need to set the callback
            self._internal_debugger.env.set_callback(_before_callback)

    @property
    def env(self: ConfigurationMixin) -> EnvDict | None:
        """The environment variables of the debugged process."""
        self._internal_debugger._ensure_process_stopped()
        return self._internal_debugger.env

    @env.setter
    def env(self: ConfigurationMixin, value: dict[str, str] | None) -> None:
        """Set the environment variables of the debugged process."""
        self._internal_debugger._ensure_process_stopped()

        # Changing env is not allowed while the process is being debugged.
        if self._internal_debugger.is_debugging:
            raise RuntimeError("Cannot change env while the process is running. Please kill it first.")

        if value is not None and not isinstance(value, dict):
            raise TypeError("env must be a dictionary or None")

        self._internal_debugger.env = EnvDict(value) if value is not None else None
        self._configure_env_dict()

    @property
    def path(self: ConfigurationMixin) -> str:
        """The resolved path to the debugged binary."""
        self._internal_debugger._ensure_process_stopped()
        return self._internal_debugger.path

    @path.setter
    def path(self: ConfigurationMixin, value: str) -> None:
        """Set the path to the debugged binary."""
        self._internal_debugger._ensure_process_stopped()
        if self._internal_debugger.is_debugging:
            raise RuntimeError("Cannot change path while the process is running. Please kill it first.")

        if not isinstance(value, str):
            raise TypeError("path must be a string")

        self._internal_debugger.clear_all_caches()

        # resolve_argv_path can fail if the path is not valid
        resolved_path = resolve_argv_path(value)

        # Changing path can also change the architecture, so we need to update it
        self.arch = elf_architecture(resolved_path)
        self._internal_debugger.path = resolved_path

        # We can also unfreeze argv[0] if it was frozen
        self._internal_debugger.argv.prevent_empty = False

        # We must note inside the debugger if the path is different from the first argument in argv
        # This must be done last, otherwise we might get in an inconsistent state
        # if one of the previous checks fails
        self._internal_debugger._has_path_different_from_argv0 = True

    @property
    def kill_on_exit(self: ConfigurationMixin) -> bool:
        """Get whether the process will be killed when the debugger exits."""
        return self._internal_debugger.kill_on_exit

    @kill_on_exit.setter
    def kill_on_exit(self: ConfigurationMixin, value: bool) -> None:
        if not isinstance(value, bool):
            raise TypeError("kill_on_exit must be a boolean")

        self._internal_debugger.kill_on_exit = value

    @property
    def signals_to_block(self: ConfigurationMixin) -> list[str]:
        """Get the signals to not forward to the process.

        Returns:
            list[str]: The signals to block.
        """
        return [resolve_signal_name(v) for v in self._internal_debugger.signals_to_block]

    @signals_to_block.setter
    def signals_to_block(self: ConfigurationMixin, signals: list[int | str]) -> None:
        """Set the signal to not forward to the process.

        Args:
            signals (list[int | str]): The signals to block.
        """
        if not isinstance(signals, list):
            raise TypeError("signals_to_block must be a list of integers or strings")

        signals = [v if isinstance(v, int) else resolve_signal_number(v) for v in signals]

        if not set(signals).issubset(get_all_signal_numbers()):
            raise ValueError("Invalid signal number.")

        self._internal_debugger.signals_to_block = signals

    @property
    def fast_memory(self: ConfigurationMixin) -> bool:
        """Get the state of the fast_memory flag.

        It is used to determine if the debugger should use a faster memory access method.

        Returns:
            bool: True if the debugger should use a faster memory access method, False otherwise.
        """
        return self._internal_debugger.fast_memory

    @fast_memory.setter
    def fast_memory(self: ConfigurationMixin, value: bool) -> None:
        """Set the state of the fast_memory flag.

        It is used to determine if the debugger should use a faster memory access method.

        Args:
            value (bool): the value to set.
        """
        self._internal_debugger._ensure_process_stopped()

        if not isinstance(value, bool):
            raise TypeError("fast_memory must be a boolean")

        # If the process is currently being debugged and we are enabling fast_memory, we must
        # ensure that fast_memory is actually available
        # Setting fast_memory to False is always allowed, and if the process is not being debugged
        # we have to perform the check at startup instead
        if (
            value
            and self._internal_debugger.is_debugging
            and not self._internal_debugger._process_memory_manager.is_available()
        ):
            raise RuntimeError(
                "The procfs memory interface could not be accessed (it could be read-only or not mounted). "
                "Fast memory access is not available for the current process.",
            )

        self._internal_debugger.fast_memory = value
