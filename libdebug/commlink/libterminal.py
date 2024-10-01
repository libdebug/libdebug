#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

import sys
import threading
from logging import StreamHandler
from pathlib import Path
from queue import Queue
from termios import TCSANOW, tcsetattr
from threading import Event
from typing import TYPE_CHECKING

from prompt_toolkit.application import Application, run_in_terminal
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.widgets import TextArea

from libdebug.commlink.std_wrapper import StdWrapper
from libdebug.debugger.internal_debugger_instance_manager import provide_internal_debugger
from libdebug.liblog import liblog

if TYPE_CHECKING:
    from prompt_toolkit.application.application import KeyPressEvent

PATH_HISTORY = Path.home() / ".cache" / "libdebug" / "history"


class LibTerminal:
    """Class that represents a terminal to interact with the child process."""

    def __init__(self: LibTerminal, prompt: str, sendline: callable, end_interactive_event: Event) -> None:
        """Initializes the LibTerminal object."""
        # Provide the internal debugger instance
        self._internal_debugger = provide_internal_debugger(self)

        # Function to send a line to the child process
        self._sendline: callable = sendline

        # Event to signal the end of the interactive session
        self.__end_interactive_event: Event = end_interactive_event

        # Initialize the message queue for the prompt_toolkit application
        self._app_message_queue: Queue = Queue()

        # Initialize the thread reference for the prompt_toolkit application
        self._app_thread: threading.Thread | None = None

        # Backup the original stdout and stderr
        self._stdout_backup: object = sys.stdout
        self._stderr_backup: object = sys.stderr

        # Content buffer for the output field. This is necessary to avoid losing the output
        # messages when the application is closed
        self._output_buffer: str = ""

        # Mouse support flag
        self._mouse_support: bool = False

        # Redirect stdout and stderr to the terminal
        sys.stdout = StdWrapper(self._stdout_backup, self)
        sys.stderr = StdWrapper(self._stderr_backup, self)

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

        # Create the history file if it does not exist
        if not PATH_HISTORY.exists():
            PATH_HISTORY.parent.mkdir(parents=True, exist_ok=True)
            PATH_HISTORY.touch()

        self._run_prompt(prompt)

    def _run_prompt(self: LibTerminal, prompt: str) -> None:
        """Run the prompt_toolkit application."""
        input_field = TextArea(
            height=3,
            prompt=prompt,
            style="class:input-field",
            history=FileHistory(str(PATH_HISTORY)),
            auto_suggest=AutoSuggestFromHistory(),
        )

        kb = KeyBindings()

        @kb.add("enter")
        def on_enter(event: KeyPressEvent) -> None:
            """Send the user input to the child process."""
            buffer = event.app.current_buffer
            cmd = buffer.text
            if cmd:
                try:
                    self._sendline(cmd.encode("ascii"))
                    buffer.history.append_string(cmd)
                except RuntimeError:
                    liblog.warning("The stdin pipe of the child process is not available anymore")
                    # Flush the output field and exit the application
                    app_exit(event)
                finally:
                    buffer.reset()

        @kb.add("c-c")
        @kb.add("c-d")
        def app_exit(event: KeyPressEvent) -> None:
            """Manage the key bindings for the exit of the application."""
            # Flush the output field
            update_output(event.app)
            # Signal the end of the interactive session
            self.__end_interactive_event.set()
            while self.__end_interactive_event.is_set():
                # Wait to be sure that the other thread is not polling from the child process's
                # stderr and stdout pipes anymore
                pass
            event.app.exit()

        @kb.add("tab")  # Replace with the key you want to use
        def accept_suggestion(event: KeyPressEvent) -> None:
            """Accept the auto-suggestion."""
            buffer = event.current_buffer
            suggestion = buffer.suggestion
            if suggestion:
                buffer.insert_text(suggestion.text)

        layout = Layout(input_field)

        app = Application(
            layout=layout,
            key_bindings=kb,
            full_screen=False,
            refresh_interval=0.5,
        )

        def update_output(app: Application) -> None:
            """Update the output field with the messages in the queue."""
            to_exit = False
            if not self._internal_debugger.running and (
                event_type := self._internal_debugger.resume_context.get_event_type()
            ):
                liblog.warning(
                    f"The debugged process has stopped due to the following event(s). {event_type}",
                )
                # Flush the output field and exit the application
                self.__end_interactive_event.set()
                to_exit = True

                while self.__end_interactive_event.is_set():
                    # Wait to be sure that the other thread is not polling from the child process
                    # stderr and stdout pipes anymore
                    pass

            # Update the output field with the messages in the queue
            msg = b""
            if not self._app_message_queue.empty():
                msg += self._app_message_queue.get()

            if msg:
                run_in_terminal(lambda: sys.stdout.buffer.write(msg))

            if to_exit:
                app.exit()

        # Add the update_output function to the event loop
        app.on_invalidate.add_handler(update_output)

        # Run in another thread
        self._app_thread = threading.Thread(target=app.run, daemon=True)
        self._app_thread.start()

    def _write_manager(self, payload: bytes) -> int:
        """Put the payload in the message queue for the prompt_toolkit application."""
        if isinstance(payload, bytes):
            self._app_message_queue.put(payload.decode("ascii", errors="backslashreplace").encode("ascii"))
        else:
            self._app_message_queue.put(payload.encode("ascii", errors="backslashreplace"))

    def reset(self: LibTerminal) -> None:
        """Reset the terminal to its original state."""
        # Wait for the prompt_toolkit application to finish
        # This (included the timeout) is necessary to avoid race conditions and deadlocks
        while self._app_thread.join(0.1):
            pass

        # Restore the original stdout and stderr
        sys.stdout = self._stdout_backup
        sys.stderr = self._stderr_backup

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

        # Restore the original stdin settings
        tcsetattr(sys.stdin.fileno(), TCSANOW, self._internal_debugger.stdin_settings_backup)
