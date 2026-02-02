#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from libdebug.data.symbol_list import SymbolList
from libdebug.liblog import liblog
from libdebug.native.libdebug_debug_sym_parser import (
    HAS_SYMBOL_SUPPORT,
    Symbol,
    TLSModuleInfo,
    collect_external_symbols,
    read_elf_info,
)
from libdebug.symbols.elf_cache_entry import ElfCacheEntry
from libdebug.utils.libcontext import libcontext

if TYPE_CHECKING:
    from libdebug.data.memory_map_list import MemoryMapList
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.native.libdebug_debug_sym_parser import SymbolBinding, SymbolType


# Paths for debug files
DEBUGINFOD_PATH: Path = Path.home() / ".cache" / "debuginfod_client"
LOCAL_DEBUG_PATH: Path = Path("/usr/lib/debug/.build-id/")
NOT_FOUND: int = 404


# Module-level cached functions for ELF checks
@lru_cache(maxsize=1024)
def _is_elf_cached(path: str) -> bool:
    """Check if a file is an ELF file (cached at module level)."""
    try:
        with Path(path).open("rb") as f:
            magic = f.read(4)
            return magic == b"\x7fELF"
    except OSError:
        return False


class SymbolManager:
    """Manages symbol resolution for a debugged process.

    This class provides a centralized interface for:
    - Parsing ELF files and extracting symbols
    - Caching symbol information for performance
    - Resolving TLS (thread-local storage) symbols
    - Handling PLT/GOT entries
    - Symbol versioning support
    """

    def __init__(self: SymbolManager, internal_debugger: InternalDebugger) -> None:
        """Initialize the symbol manager.

        Args:
            internal_debugger: The internal debugger instance.
        """
        self._debugger = internal_debugger
        self._elf_cache: dict[str, ElfCacheEntry] = {}
        self._symbol_cache: dict[str, list[Symbol]] = {}
        self._symbol_name_index: dict[str, dict[str, Symbol]] = {}  # path -> name -> symbol
        self._tls_modules: dict[str, TLSModuleInfo] = {}
        self._next_tls_module_id = 1

    def clear_cache(self: SymbolManager) -> None:
        """Clear all cached symbol information."""
        self._elf_cache.clear()
        self._symbol_cache.clear()
        self._symbol_name_index.clear()
        self._tls_modules.clear()
        self._next_tls_module_id = 1
        # Also clear module-level caches
        _is_elf_cached.cache_clear()

    @staticmethod
    def _set_symbol_context(
        sym: Symbol,
        backing_file: str,
        reference_file: str,
        build_id: str | None,
        is_external: bool,
    ) -> Symbol:
        """Set runtime context fields on a native Symbol object.

        The Symbol object comes from C++ with most fields already populated.
        This method sets the runtime context that the parser doesn't know about.
        """
        sym.backing_file = backing_file
        sym.reference_file = reference_file
        sym.reference_build_id = build_id or ""
        sym.is_external = is_external
        return sym

    def parse_elf(self: SymbolManager, path: str, force: bool = False) -> ElfCacheEntry:
        """Parse an ELF file and extract symbol information.

        Args:
            path: Path to the ELF file.
            force: If True, re-parse even if cached.

        Returns:
            ElfCacheEntry with parsed information.
        """
        if not force and path in self._elf_cache:
            return self._elf_cache[path]

        if libcontext.sym_lvl == 0:
            # Symbol resolution disabled
            entry = ElfCacheEntry()
            self._elf_cache[path] = entry
            return entry

        if not HAS_SYMBOL_SUPPORT:
            liblog.warning("Symbol support not available - libdebug was built without libdwarf/libelf")
            entry = ElfCacheEntry()
            self._elf_cache[path] = entry
            return entry

        try:
            liblog.debugger("Parsing ELF file: %s", path)
            elf_info = read_elf_info(path, libcontext.sym_lvl)

            tls_info = None
            if hasattr(elf_info, "tls_info") and elf_info.tls_info.tls_block_size > 0:
                tls_info = elf_info.tls_info
                tls_info.module_id = self._next_tls_module_id
                self._tls_modules[path] = tls_info
                self._next_tls_module_id += 1

            entry = ElfCacheEntry(
                symbols=elf_info.symbols,
                build_id=elf_info.build_id or None,
                debug_link=elf_info.debuglink or None,
                is_pie=getattr(elf_info, "is_pie", False),
                entry_point=getattr(elf_info, "entry_point", 0),
                tls_info=tls_info,
            )

            self._elf_cache[path] = entry
            return entry  # noqa: TRY300

        except Exception as e:  # noqa: BLE001
            liblog.error("Failed to parse ELF file %s: %s", path, e)
            entry = ElfCacheEntry()
            self._elf_cache[path] = entry
            return entry

    def _collect_external_symbols(
        self: SymbolManager,
        debug_path: str,
        reference_path: str,
        build_id: str | None,
    ) -> list[Symbol]:
        """Collect symbols from an external debug file."""
        if not HAS_SYMBOL_SUPPORT:
            return []

        cache_key = f"ext:{debug_path}"
        if cache_key in self._symbol_cache:
            return self._symbol_cache[cache_key]

        try:
            liblog.debugger("Collecting external symbols from: %s", debug_path)
            ext_symbols = collect_external_symbols(debug_path, reference_path, build_id, libcontext.sym_lvl)
        except Exception as e:  # noqa: BLE001
            liblog.error("Failed to collect external symbols from %s: %s", debug_path, e)
            return []
        else:
            self._symbol_cache[cache_key] = ext_symbols
            return ext_symbols

    def _download_debuginfod(self: SymbolManager, build_id: str) -> Path | None:
        """Download debug info from debuginfod server."""
        import requests

        debuginfod_path = DEBUGINFOD_PATH / build_id / "debuginfo"

        if debuginfod_path.exists():
            # Check if it's an empty placeholder (not found previously)
            if debuginfod_path.stat().st_size == 0:
                return None
            return debuginfod_path

        try:
            url = libcontext.debuginfod_server + "buildid/" + build_id + "/debuginfo"
            r = requests.get(url, allow_redirects=True, timeout=5)

            if r.ok:
                content = r.content
            elif r.status_code == NOT_FOUND:
                liblog.debugger("Debuginfo for %s not found on debuginfod", build_id)
                content = b""  # Cache the miss
            else:
                liblog.warning("Failed to download debuginfo: HTTP %d", r.status_code)
                return None

            debuginfod_path.parent.mkdir(parents=True, exist_ok=True)
            with debuginfod_path.open("wb") as f:
                f.write(content)

            if len(content) == 0:
                return None
            return debuginfod_path  # noqa: TRY300

        except Exception as e:  # noqa: BLE001
            liblog.debugger("Exception downloading debuginfod: %s", e)
            return None

    def get_symbols_for_file(self: SymbolManager, path: str) -> list[Symbol]:
        """Get all symbols for a given file, including external debug info.

        Args:
            path: Path to the ELF file.

        Returns:
            List of Symbol objects.
        """
        # Check cache first
        cache_key = f"full:{path}:{libcontext.sym_lvl}"
        if cache_key in self._symbol_cache:
            return self._symbol_cache[cache_key]

        all_symbols: list[Symbol] = []

        # Parse the main ELF file
        entry = self.parse_elf(path)
        all_symbols.extend(entry.symbols)

        if libcontext.sym_lvl <= 2:  # noqa: PLR2004
            return all_symbols

        # Look for external debug symbols via .gnu_debuglink
        if entry.build_id and entry.debug_link and libcontext.sym_lvl > 2:  # noqa: PLR2004
            folder = entry.build_id[:2]
            debug_path = LOCAL_DEBUG_PATH / folder / entry.debug_link

            if debug_path.exists():
                ext_symbols = self._collect_external_symbols(
                    str(debug_path),
                    path,
                    entry.build_id,
                )
                all_symbols.extend(ext_symbols)

        # Try debuginfod
        if entry.build_id and libcontext.sym_lvl > 4:  # noqa: PLR2004
            debuginfod_path = self._download_debuginfod(entry.build_id)
            if debuginfod_path:
                ext_symbols = self._collect_external_symbols(
                    str(debuginfod_path),
                    path,
                    entry.build_id,
                )
                all_symbols.extend(ext_symbols)

        # Cache the full symbol list
        self._symbol_cache[cache_key] = all_symbols
        return all_symbols

    def get_all_symbols(self: SymbolManager, maps: MemoryMapList) -> SymbolList[Symbol]:
        """Get all symbols for all mapped files in the process.

        Args:
            maps: Memory map list from the debugger.

        Returns:
            SymbolList containing all symbols.
        """
        all_symbols: list[Symbol] = []
        seen_files: set[str] = set()

        for vmap in maps:
            backing_file = vmap.backing_file
            if not backing_file or backing_file.startswith("[") or backing_file in seen_files:
                continue

            seen_files.add(backing_file)

            # Check if it's an ELF file
            if not self._is_elf(backing_file):
                continue

            try:
                symbols = self.get_symbols_for_file(backing_file)
                all_symbols.extend(symbols)
            except Exception as e:  # noqa: BLE001
                liblog.debugger("Failed to get symbols for %s: %s", backing_file, e)

        return SymbolList(all_symbols, self._debugger)

    def _is_elf(self: SymbolManager, path: str) -> bool:
        """Check if a file is an ELF file (uses module-level cache)."""
        # Check if we already know about this file from the ELF cache
        if path in self._elf_cache:
            return True
        return _is_elf_cached(path)

    def _get_symbol_by_name(self: SymbolManager, path: str, name: str) -> Symbol | None:
        """Get a symbol by name from a file using O(1) index lookup.

        Args:
            path: Path to the ELF file.
            name: Symbol name to look up.

        Returns:
            The symbol if found, None otherwise.
        """
        # Build or get the name index for this file
        cache_key = f"full:{path}:{libcontext.sym_lvl}"

        if cache_key not in self._symbol_name_index:
            # Ensure symbols are loaded first
            symbols = self.get_symbols_for_file(path)

            # Build the name index
            name_index: dict[str, Symbol] = {}
            for sym in symbols:
                if sym.name and sym.name not in name_index:
                    name_index[sym.name] = sym
                if sym.demangled_name and sym.demangled_name not in name_index:
                    name_index[sym.demangled_name] = sym

            self._symbol_name_index[cache_key] = name_index

        return self._symbol_name_index[cache_key].get(name)

    def resolve_symbol(self: SymbolManager, symbol: str, maps: MemoryMapList) -> int:
        """Resolve a symbol name to an address.

        Args:
            symbol: Symbol name (may include +offset).
            maps: Memory maps to search in.

        Returns:
            The resolved address.

        Raises:
            ValueError: If the symbol is not found.
        """
        offset = 0
        if "+" in symbol:
            symbol, offset_str = symbol.split("+", 1)
            offset = int(offset_str, 16)

        # Track files we've already searched
        seen_files: set[str] = set()

        # Search all mapped files
        for vmap in maps:
            backing_file = vmap.backing_file
            if not backing_file or backing_file.startswith("[") or backing_file in seen_files:
                continue

            seen_files.add(backing_file)

            if not self._is_elf(backing_file):
                continue

            try:
                # Fast O(1) lookup by name (includes external debug symbols)
                sym = self._get_symbol_by_name(backing_file, symbol)
                if sym is not None:
                    # Get ELF info for PIE check
                    entry = self.parse_elf(backing_file)
                    base_address = vmap.start if entry.is_pie else 0
                    return sym.start + base_address + offset

            except Exception as e:  # noqa: BLE001
                liblog.debugger("Error resolving symbol in %s: %s", backing_file, e)

        raise ValueError(f"Symbol '{symbol}' not found")

    def resolve_address(self: SymbolManager, address: int, maps: MemoryMapList) -> str:
        """Resolve an address to a symbol name.

        Args:
            address: The address to resolve.
            maps: Memory maps to search in.

        Returns:
            Symbol name with offset (e.g., "func+0x10") or hex address.
        """
        # Find the backing file for this address
        target_map = None
        for vmap in maps:
            if vmap.start <= address < vmap.end:
                target_map = vmap
                break

        if not target_map or not target_map.backing_file or target_map.backing_file.startswith("["):
            return hex(address)

        backing_file = target_map.backing_file

        try:
            entry = self.parse_elf(backing_file)

            # Calculate file-relative address for PIE
            # For PIE, we need the base address (first segment with offset 0)
            file_addr = address
            if entry.is_pie:
                # Find the base address - first mapping of this file
                base_address = None
                for vmap in maps:
                    if vmap.backing_file == backing_file:
                        base_address = vmap.start - vmap.offset
                        break
                if base_address is not None:
                    file_addr = address - base_address

            # Search for containing symbol (uses cache)
            all_symbols = self.get_symbols_for_file(backing_file)
            for sym in all_symbols:
                if sym.start <= file_addr < sym.end:
                    offset = file_addr - sym.start
                    if offset == 0:
                        return sym.display_name
                    return f"{sym.display_name}+{offset:x}"

        except Exception as e:  # noqa: BLE001
            liblog.debugger("Error resolving address %#x: %s", address, e)

        return hex(address)

    def get_tls_address(
        self: SymbolManager,
        symbol: Symbol,
        _thread_id: int,
        fs_base: int | None = None,
        _gs_base: int | None = None,
    ) -> int | None:
        """Resolve the address of a TLS symbol for a specific thread.

        Args:
            symbol: The TLS symbol to resolve.
            _thread_id: The thread ID (reserved for future use).
            fs_base: The FS segment base (x86-64 TLS pointer).
            _gs_base: The GS segment base (reserved for future use).

        Returns:
            The resolved address, or None if resolution failed.
        """
        if not symbol.is_tls or symbol.tls_offset is None:
            return None

        # On x86-64 Linux, TLS is accessed via FS segment
        # The layout is: fs_base points to the thread control block (TCB)
        # TLS variables are at negative offsets from fs_base for static TLS
        # or positive offsets for dynamic TLS

        if fs_base is None:
            return None

        # For the main executable and preloaded libraries (static TLS),
        # the offset is negative from fs_base
        # For dynamically loaded libraries, we need to use __tls_get_addr

        backing_file = symbol.backing_file
        tls_info = self._tls_modules.get(backing_file)

        # For external debug symbols, backing_file points to the debug file,
        # but TLS modules are indexed by the loaded ELF path (reference_file)
        if tls_info is None and symbol.is_external and symbol.reference_file:
            tls_info = self._tls_modules.get(symbol.reference_file)

        if tls_info is not None:
            # Static TLS: offset from fs_base
            # The TLS block is at a negative offset from fs_base
            # tls_offset is the offset within the TLS block
            return fs_base - tls_info.tls_block_size + symbol.tls_offset
        else:
            # Dynamic TLS - would need to call __tls_get_addr
            # This is complex and requires injecting code or reading internal structures
            liblog.warning(
                "Dynamic TLS resolution for %s not fully supported yet",
                symbol.name,
            )
            return None

    def filter_symbols(  # noqa: PLR0913
        self: SymbolManager,
        symbols: list[Symbol],
        *,
        name: str | None = None,
        symbol_type: SymbolType | None = None,
        binding: SymbolBinding | None = None,
        tls_only: bool = False,
        functions_only: bool = False,
        objects_only: bool = False,
        defined_only: bool = False,
    ) -> list[Symbol]:
        """Filter symbols by various criteria.

        Args:
            symbols: List of symbols to filter.
            name: Filter by name (substring match).
            symbol_type: Filter by symbol type.
            binding: Filter by binding.
            tls_only: Only return TLS symbols.
            functions_only: Only return function symbols.
            objects_only: Only return object/data symbols.
            defined_only: Only return defined (not undefined) symbols.

        Returns:
            Filtered list of symbols.
        """
        result = symbols

        if name:
            result = [s for s in result if name in s.name or name in (s.demangled_name or "")]

        if symbol_type is not None:
            result = [s for s in result if s.symbol_type == symbol_type]

        if binding is not None:
            result = [s for s in result if s.binding == binding]

        if tls_only:
            result = [s for s in result if s.is_tls]

        if functions_only:
            result = [s for s in result if s.is_function]

        if objects_only:
            result = [s for s in result if s.is_object]

        if defined_only:
            result = [s for s in result if s.is_defined]

        return result
