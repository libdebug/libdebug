#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025  Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.liblog import liblog


def find_all_overlapping_occurrences(pattern: bytes, data: bytes, abs_address: int = 0) -> list[int]:
    """Find all overlapping occurrences of a pattern in a data."""
    start = 0
    occurrences = []
    while True:
        start = data.find(pattern, start)
        if start == -1:
            # No more occurrences
            break
        occurrences.append(start + abs_address)
        # Increment start to find overlapping matches
        start += 1
    return occurrences


class AhoCorasickMatcher:
    """
    Simplified Aho-Corasick algorithm implementation for multiple pattern searching.

    With respect to the original Aho-Corasick procedure, we stop at the first matched pattern.
    """

    class _Node:
        """A node in the Aho-Corasick trie."""

        def __init__(self: AhoCorasickMatcher._Node, pattern: str) -> None:
            self.pattern = pattern
            # Children nodes mapped by byte value
            self.children: dict[int, AhoCorasickMatcher._Node] = {}
            # Fail link = None is only when uninitialized, otherwise it points to root at least
            self.fail_link: AhoCorasickMatcher._Node | None = None
            # Index of the pattern if this node represents the end of a pattern, -1 otherwise
            self.output: int = -1

    def __init__(self: AhoCorasickMatcher, patterns: list[bytes]) -> None:
        """State of the simplified Aho-Corasick procedure."""
        self.root = self._Node(b"")
        self.patterns = patterns
        self.state = self.root
        self.consumed_bytes = bytearray()  # O(1) append
        self._build_trie()
        self._build_failure_links()

    def _build_trie(self) -> None:
        for pattern in self.patterns:
            curr_node = self.root
            shadowed = False
            for i, char in enumerate(pattern):
                # 1. Traverse or Create Child
                if char not in curr_node.children:
                    new_node = self._Node(curr_node.pattern + bytes([char]))
                    curr_node.children[char] = new_node

                curr_node = curr_node.children[char]

                # 2. Check for Prefix Shadowing
                if curr_node.output != -1 and i < len(pattern) - 1 and not shadowed:
                    liblog.warning(
                        "Pattern '%s' has a prefix matching another pattern. This pattern will be ignored.",
                        pattern,
                    )
                    shadowed = True

                # 3. Mark Output
                if i == len(pattern) - 1:
                    if curr_node.output != -1:
                        liblog.warning(
                            "Pattern '%s' is a duplicate of another pattern. This pattern will be ignored.",
                            pattern,
                        )
                    curr_node.output = self.patterns.index(pattern)

    def _build_failure_links(self) -> None:
        queue = []

        self.root.fail_link = self.root

        # 1. Handle depth 1 (children of root)
        for child in self.root.children.values():
            child.fail_link = self.root
            queue.append(child)

        # 2. BFS
        while len(queue) > 0:
            parent_node = queue.pop(0)  # We are currently at the PARENT

            # Calculate fail links for all children of this parent
            for char, child_node in parent_node.children.items():
                # Start with the parent's fail link
                fail_candidate = parent_node.fail_link

                # Keep going up until we find a match or hit root
                while fail_candidate is not self.root and char not in fail_candidate.children:
                    fail_candidate = fail_candidate.fail_link

                if char in fail_candidate.children:
                    child_node.fail_link = fail_candidate.children[char]
                else:
                    child_node.fail_link = self.root

                queue.append(child_node)

    def stateful_search(self: AhoCorasickMatcher, data: bytes) -> tuple[int, int]:
        """
        Search for patterns in the data. Maintains the state of the search.

        Args:
            data (bytes): The data to search within.

        Returns:
            tuple[int, int]: (pattern_index, end_index_in_data)
                             pattern_index is -1 if not found.
                             end_index_in_data is the index in 'data' immediately after the match.
        """
        curr_index = 0
        while curr_index < len(data):
            curr_char = data[curr_index]

            if curr_char in self.state.children:
                self.state = self.state.children[curr_char]
                self.consumed_bytes.append(curr_char)
                curr_index += 1

                if self.state.output != -1:
                    return self.state.output, curr_index
            else:
                if self.state is self.root:
                    self.consumed_bytes.append(curr_char)
                    curr_index += 1

                self.state = self.state.fail_link

        return -1, -1
