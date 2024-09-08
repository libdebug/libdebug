#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import sys
import tty
from functools import wraps
from logging import StreamHandler
from termios import TCSADRAIN, tcgetattr, tcsetattr

from libdebug.liblog import liblog
from libdebug.utils.ansi_escape_codes import ANSIKeyboadStrings, ANSIPrivateModes


def known_manager_preliminary_operations(method: callable) -> callable:
    """Decorator to perform preliminary operations before executing a known manager."""

    @wraps(method)
    def wrapper(self: LibTerminal, payload: bytes) -> ...:
        # If the paylpad is not ascii, we need to escape it.
        # This is not strictly necessary, but it is useful to improve the readability of the output
        payload = payload.decode("ascii", errors="backslashreplace").encode()

        # Escape the ANSI escape prefix
        if payload == ANSIKeyboadStrings.ESCAPE_KEY:
            payload = b"\\x1b"

        # Move the cursor to the beginning of the line
        self._clear_row()

        # Update the ANSI escape sequence buffer. This is necessary to move the cursor correctly
        # according to the stdin buffer index
        self._ansi_buffer = ANSIKeyboadStrings.LEFT_ARROW_KEY * (len(self._stdin_buffer) - self._stdin_index)

        return method(self, payload)

    return wrapper


def unknown_manager_preliminary_operations(method: callable) -> callable:
    """Decorator to perform preliminary operations before executing an unknown manager."""

    @wraps(method)
    def wrapper(self: LibTerminal, payload: bytes | str) -> ...:
        # If the payload is a string, we need to convert it to bytes
        # (this is necessary because we do not know the source of the payload)
        if isinstance(payload, str):
            payload = payload.encode()

        # Move the cursor to the beginning of the line
        self._clear_row()

        # Replace newline characters with newline + carriage return
        payload = payload.replace(b"\n", b"\n\r")

        # Update the ANSI escape sequence buffer. This is necessary to move the cursor correctly
        # according to the stdin buffer index
        self._ansi_buffer = ANSIKeyboadStrings.LEFT_ARROW_KEY * (len(self._stdin_buffer) - self._stdin_index)

        return method(self, payload)

    return wrapper


class LibTerminal:
    """Class that represents a terminal to interact with the child process."""

    def __init__(self: LibTerminal, prompt: bytes) -> None:
        """Initializes the LibTerminal object."""
        # Initialize the buffers
        self._stdout_buffer: bytes = b""
        self._stdin_buffer: bytes = b""
        self._stderr_buffer: bytes = b""
        self._ansi_buffer: bytes = b""

        # Initialize the escape sequence variables
        self._escape_sequence: bytes = b""
        self._longest_escape_sequence: int = ANSIKeyboadStrings.get_longest_key_length()

        # Initialize the stdin index to keep track of the current position in the stdin buffer
        self._stdin_index = 0

        # Set the terminal prompt
        self._prompt: bytes = prompt

        # Shortcut to the stdout and stderr buffer objects
        self._stdout: object = sys.stdout.buffer
        self._stderr: object = sys.stderr.buffer

        # Backup the original stdout and stderr
        self._stdout_backup: object = sys.stdout
        self._stderr_backup: object = sys.stderr
        self._stdin_backup: object = sys.stdin

        # Redirect stdout and stderr to the terminal
        sys.stdout = StdoutWrapper(self._stdout_backup, self)
        sys.stderr = StderrWrapper(self._stderr_backup, self)
        sys.stdin = StdinWrapper(self._stdin_backup, self)

        # Redirect the loggers to the terminal
        for handler in liblog.general_logger.handlers:
            if isinstance(handler, StreamHandler):
                handler.stream = sys.stderr

        for handler in liblog.pipe_logger.handlers:
            if isinstance(handler, StreamHandler):
                handler.stream = sys.stderr

        for handler in liblog.debugger_logger.handlers:
            if isinstance(handler, StreamHandler):
                handler.stream = sys.stderr

        # Set the stdin to raw mode
        self._stdin_settings_backup = tcgetattr(self._stdin_backup.fileno())
        tty.setraw(self._stdin_backup.fileno())

        # Activate the cursor for the user input. This avoids conflicts with some libraries or terminal settings 
        # that hide the cursor.
        self._stdout.write(ANSIPrivateModes.SHOW_CURSOR)
        self._stderr.flush()

    @property
    def stdin_buffer(self: LibTerminal) -> bytes:
        """Returns the current stdin buffer."""
        return self._stdin_buffer

    def clear_stdin_buffer(self: LibTerminal) -> None:
        """Clears the stdin buffer."""
        self._stdin_buffer = b""
        self._stdin_index = 0

    def _clear_row(self) -> None:
        """Clears the current row."""
        number_of_chars_stdout = len(self._stdout_buffer) + len(self._stdin_buffer) + len(self._prompt)
        self._stderr.write(b"\r" + b" " * number_of_chars_stdout + b"\r")

        number_of_chars_stderr = len(self._stderr_buffer) + len(self._stdin_buffer) + len(self._prompt)
        self._stderr.write(b"\r" + b" " * number_of_chars_stderr + b"\r")

    @known_manager_preliminary_operations
    def _write_from_known_stdout_manager(self, payload: bytes) -> int:
        """Writes data coming from the stdout pipe of the child process."""
        # Write the stderr buffer to the console stderr
        self._stderr.write(self._stderr_buffer)

        # Write the data to the console stdout
        self._stdout_buffer += payload
        if payload == b"\n":
            # Add a carriage return character at the end of the line
            self._stdout_buffer += b"\r"
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer + self._ansi_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()

        # If the payload is a newline character, we need to clear the stdout buffer
        if payload == b"\n":
            self._stdout_buffer = b""

        return len(payload)

    @known_manager_preliminary_operations
    def _write_from_known_stderr_manager(self, payload: bytes) -> int:
        """Writes data coming from the stderr pipe of the child process."""
        # Write the data to the console stderr
        self._stderr_buffer += payload
        if payload == b"\n":
            # Add a carriage return character at the end of the line
            self._stderr_buffer += b"\r"
        self._stderr.write(self._stderr_buffer)

        # Write the stdout buffer, the prompt, and the stdin buffer on the console stdout
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer + self._ansi_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()

        # If the payload is a newline character, we need to clear the stderr buffer
        if payload == b"\n":
            self._stderr_buffer = b""

        return len(payload)

    @known_manager_preliminary_operations
    def _write_from_stdin_manager(self, payload: bytes) -> int:
        """Writes data coming from the stdin pipe of the child process."""
        # Write the stderr buffer to the console stderr
        self._stderr.write(self._stderr_buffer)

        # Add the payload to the stdin buffer in the correct position
        if self._stdin_index == len(self._stdin_buffer) - 1:
            self._stdin_buffer += payload
        else:
            self._stdin_buffer = (
                self._stdin_buffer[: self._stdin_index] + payload + self._stdin_buffer[self._stdin_index :]
            )
        self._stdin_index += len(payload)

        # Write the data to the console stdout
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer + self._ansi_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()

        return len(payload)

    @unknown_manager_preliminary_operations
    def _write_from_unknown_stdout_manager(self, payload: bytes | str) -> int:
        """Writes data coming from an unknown source."""
        # Write the data to the console stderr
        self._stdout.write(payload)

        # Write the stderr buffer to the console stderr
        self._stderr.write(self._stderr_buffer)

        # Write the stdout buffer, the prompt, and the stdin buffer on the console stdout
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer + self._ansi_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()
        return len(payload)

    @unknown_manager_preliminary_operations
    def _write_from_unknown_stderr_manager(self, payload: bytes | str) -> int:
        """Writes data coming from an unknown source."""
        # Write the data to the console stderr
        self._stderr.write(payload)

        # Write the stderr buffer to the console stderr
        self._stderr.write(self._stderr_buffer)

        # Write the stdout buffer, the prompt, and the stdin buffer on the console stdout
        self._stdout.write(self._stdout_buffer + self._prompt + self._stdin_buffer + self._ansi_buffer)

        # Flush the buffers
        self._stderr.flush()
        self._stdout.flush()
        return len(payload)

    def _stdin_escape_sequence_manager(self, char: bytes) -> None:
        """Manages the stdin escape sequences."""
        # Add the character to the escape sequence
        self._escape_sequence += char
        if len(self._escape_sequence) == self._longest_escape_sequence:
            match self._escape_sequence:
                # We are interested only in the escape sequences that move the cursor
                case ANSIKeyboadStrings.RIGHT_ARROW_KEY | ANSIKeyboadStrings.RIGHT_ARROW_KEYPAD:
                    if self._stdin_index < len(self._stdin_buffer):
                        self._stdin_index += 1
                    self._write_from_stdin_manager(b"")
                case ANSIKeyboadStrings.LEFT_ARROW_KEY | ANSIKeyboadStrings.LEFT_ARROW_KEYPAD:
                    if self._stdin_index > 0:
                        self._stdin_index -= 1
                    self._write_from_stdin_manager(b"")
                case _:
                    # This is not an interesting escape sequence
                    for el in self._escape_sequence:
                        self._write_from_stdin_manager(bytes([el]))
            # Clear the escape sequence
            self._escape_sequence = b""

    def stdin_buffer_manager(self, char: bytes) -> None:
        """Manages the stdin buffer."""
        match char:
            case ANSIKeyboadStrings.DELETE_KEY:
                if self._stdin_index > 0:
                    self._stdin_buffer = (
                        self._stdin_buffer[: self._stdin_index - 1] + self._stdin_buffer[self._stdin_index :]
                    )
                    self._stdin_index -= 1
                self._write_from_stdin_manager(b"")
            case ANSIKeyboadStrings.ESCAPE_KEY:
                self._escape_sequence += char
            case ANSIKeyboadStrings.CTRL_C_KEY:
                raise KeyboardInterrupt
            case ANSIKeyboadStrings.CTRL_D_KEY:
                raise EOFError
            case _:
                if self._escape_sequence:
                    # This is part of an escape sequence
                    self._stdin_escape_sequence_manager(char)
                else:
                    # Add the character to the stdin buffer
                    self._write_from_stdin_manager(char)

    def reset(self: LibTerminal) -> None:
        """Resest the terminal to its original state."""
        # Restore the original stdout and stderr
        sys.stdout = self._stdout_backup
        sys.stderr = self._stderr_backup
        sys.stdin = self._stdin_backup

        # Restore the loggers
        for handler in liblog.general_logger.handlers:
            if isinstance(handler, StreamHandler):
                handler.stream = sys.stderr

        for handler in liblog.pipe_logger.handlers:
            if isinstance(handler, StreamHandler):
                handler.stream = sys.stderr

        for handler in liblog.debugger_logger.handlers:
            if isinstance(handler, StreamHandler):
                handler.stream = sys.stderr

        # Restore the stdin settings
        tcsetattr(sys.stdin.fileno(), TCSADRAIN, self._stdin_settings_backup)


class StdoutWrapper:
    """Wrapper around stdout to allow for custom write method."""

    def __init__(self: StdoutWrapper, fd: object, terminal: LibTerminal) -> None:
        """Initializes the StdoutWrapper object."""
        self._fd: object = fd
        self._terminal: LibTerminal = terminal

    def write(self, payload: bytes | str) -> int:
        """Overloads the write method to allow for custom behavior."""
        return self._terminal._write_from_unknown_stdout_manager(payload)

    def write_known_source(self, payload: bytes | str) -> int:
        """Custom write method for known sources."""
        return self._terminal._write_from_known_stdout_manager(payload)

    def __getattr__(self, k: any) -> any:
        """Ensure that all other attributes are forwarded to the original file descriptor."""
        return getattr(self._fd, k)


class StderrWrapper:
    """Wrapper around stderr to allow for custom write method."""

    def __init__(self: StderrWrapper, fd: object, terminal: LibTerminal) -> None:
        """Initializes the StderrWrapper object."""
        self._fd: object = fd
        self._terminal: LibTerminal = terminal

    def write(self, payload: bytes | str) -> int:
        """Overloads the write method to allow for custom behavior."""
        return self._terminal._write_from_unknown_stderr_manager(payload)

    def write_known_source(self, payload: bytes | str) -> int:
        """Custom write method for known sources."""
        return self._terminal._write_from_known_stderr_manager(payload)

    def __getattr__(self, k: any) -> any:
        """Ensure that all other attributes are forwarded to the original file descriptor."""
        return getattr(self._fd, k)


class StdinWrapper:
    """Wrapper around stdin to allow for custom read method."""

    def __init__(self: StdinWrapper, fd: object, terminal: LibTerminal) -> None:
        """Initializes the StdinWrapper object."""
        self._fd: object = fd
        self._terminal: LibTerminal = terminal

    def readline_known_source(self) -> bytes:
        """Custom readline method for known sources."""
        char = b""
        while True:
            char = self._fd.read(1).encode()
            if char == ANSIKeyboadStrings.ENTER_KEY:
                # The terminal is set to raw mode, so the Enter key sends a carriage return character
                # instead of a newline character. We need to convert it to a newline character.
                recv_stdin = self._terminal.stdin_buffer + b"\n"
                self._terminal.clear_stdin_buffer()
                return recv_stdin
            else:
                self._terminal.stdin_buffer_manager(char)

    def __getattr__(self, k: any) -> any:
        """Ensure that all other attributes are forwarded to the original file descriptor."""
        return getattr(self._fd, k)
