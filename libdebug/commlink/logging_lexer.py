#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from prompt_toolkit.lexers import Lexer

from libdebug.utils.ansi_escape_codes import ANSIColors

if TYPE_CHECKING:
    from prompt_toolkit.document import Document


class LoggingLexer(Lexer):
    """Lexer to colorize the output of the terminal."""

    patterns: ClassVar[list[str]] = [
        f"[{ANSIColors.BRIGHT_YELLOW}WARNING{ANSIColors.DEFAULT_COLOR}]",
        f"[{ANSIColors.RED}ERROR{ANSIColors.DEFAULT_COLOR}]",
        f"[{ANSIColors.GREEN}INFO{ANSIColors.DEFAULT_COLOR}]",
    ]

    def lex_document(self: LoggingLexer, document: Document) -> callable[[int], list[tuple[str, str]]]:
        """Return a callable that takes a line number and returns a list of tokens for that line."""

        def get_line_tokens(line_number: int) -> list[tuple[str, str]]:
            line = document.lines[line_number]
            tokens = []
            if self.patterns[0] in line:
                line = line.split(self.patterns[0])
                tokens.append(("", line[0]))
                tokens.append(("", "["))
                tokens.append(("class:warning", "WARNING"))
                tokens.append(("", "]"))
                tokens.append(("", line[1]))
            elif line.startswith(self.patterns[1]):
                line = line.split(self.patterns[1])
                tokens.append(("", line[0]))
                tokens.append(("", "["))
                tokens.append(("class:error", "ERROR"))
                tokens.append(("", "]"))
                tokens.append(("", line[1]))
            elif line.startswith(self.patterns[2]):
                line = line.split(self.patterns[2])
                tokens.append(("", line[0]))
                tokens.append(("", "["))
                tokens.append(("class:info", "INFO"))
                tokens.append(("", "]"))
                tokens.append(("", line[1]))
            else:
                tokens.append(("", line))
            return tokens

        return get_line_tokens
