#
# Copyright (c) 2023-2024  Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#


def find_all_overlapping_occurrences(pattern: bytes, data: bytes) -> list[int]:
    """Find all overlapping occurrences of a pattern in a data."""
    start = 0
    occurrences = []
    while True:
        start = data.find(pattern, start)
        if start == -1:
            # No more occurrences
            break
        occurrences.append(start)
        # Increment start to find overlapping matches
        start += 1
    return occurrences
