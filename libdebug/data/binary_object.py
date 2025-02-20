#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from hashlib import md5, sha1, sha256, sha512
from pathlib import Path


class BinaryObject:
    """A binary object involved in the debugging session."""

    def __init__(self: BinaryObject, path: str, is_library: bool) -> None:
        """
        Initialize a BinaryObject instance with the given file path.

        Args:
            path (str): The file path to the binary object.
            is_library (bool): Whether the binary object is a library or not.
        """
        self.path = path
        self.is_library = is_library
        self._data = None

        # Info cache
        self._sections = None
        self._symbols = None
        self._build_id = None
        self._entry_point = None
        self._md5sum = None
        self._sha1sum = None
        self._sha256sum = None
        self._sha512sum = None
        self._size = None

    @property
    def sections(self: BinaryObject) -> list[str]:
        """Return the sections of the binary object."""
        raise NotImplementedError

    @property
    def symbols(self: BinaryObject) -> list[str]:
        """Return the symbols of the binary object."""
        raise NotImplementedError

    @property
    def data(self: BinaryObject) -> bytes:
        """Return the data of the binary object."""
        with Path(self.path).open("rb") as f:
            self._data = f.read()

        return self._data

    @property
    def build_id(self: BinaryObject) -> str:
        """Return the build ID of the binary object."""
        raise NotImplementedError

    @property
    def entry_point(self: BinaryObject) -> int:
        """Return the entry point of the binary object."""
        raise NotImplementedError

    @property
    def md5sum(self: BinaryObject) -> str:
        """Return the MD5 checksum of the binary object."""
        if self._md5sum is None:
            self._md5sum = md5(self.data).hexdigest()

        return self._md5sum

    @property
    def sha1sum(self: BinaryObject) -> str:
        """Return the SHA-1 checksum of the binary object."""
        if self._sha1sum is None:
            self._sha1sum = sha1(self.data).hexdigest()

        return self._sha1sum

    @property
    def sha256sum(self: BinaryObject) -> str:
        """Return the SHA-256 checksum of the binary object."""
        if self._sha256sum is None:
            self._sha256sum = sha256(self.data).hexdigest()

        return self._sha256sum

    @property
    def sha512sum(self: BinaryObject) -> str:
        """Return the SHA-512 checksum of the binary object."""
        if self._sha512sum is None:
            self._sha512sum = sha512(self.data).hexdigest()

        return self._sha512sum

    @property
    def size(self: BinaryObject) -> int:
        """Return the size of the binary object."""
        if self._size is None:
            self._size = Path(self.path).stat().st_size

        return self._size
