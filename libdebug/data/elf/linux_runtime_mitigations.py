from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from libdebug.native.libdebug_elf_api import quick_sym_heuristic_lookup

if TYPE_CHECKING:
    from libdebug.data.elf.elf import ELF


class RelroStatus(str, Enum):
    """Enumeration for RELRO (Relocation Read-Only) status."""

    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


@dataclass(frozen=True)
class LinuxRuntimeMitigations:
    """Represents the Linux runtime mitigations for a process.

    Attributes:
        relro (RelroStatus): RELRO (Relocation Read-Only)
        stack_guard (bool): Stack canary (stack guard) enabled or not.
        nx (bool): Non-Executable (NX) stack enabled or not.
        stack_executable (bool): Stack is executable or not.
        pie (bool): Position-Independent Executable (PIE) enabled or not.
        shstk (bool): Intel CET / ARM GCS Shadow Stack (SHSTK) supported.
        ibt (bool): Intel CET Indirect Branch Tracking (IBT) supported.
        fortify (bool): Glibc FORTIFY_SOURCE enabled or not.
        mte (bool): ARM Memory Tagging Extension (MTE) supported.
        pac (bool): ARM Pointer Authentication Codes (PAC) supported.
        asan (bool): Binary built with Address Sanitizer (ASAN).
        msan (bool): Binary built with Memory Sanitizer (MSAN).
        ubsan (bool): Binary built with Undefined Behavior Sanitizer (UBSAN).
    """

    relro: RelroStatus = RelroStatus.NONE
    """RELRO (Relocation Read-Only) status, can be 'full', 'partial', or 'none'."""

    stack_guard: bool = False
    """Stack canary (stack guard) enabled or not."""

    nx: bool = False
    """Non-Executable (NX) stack enabled or not."""

    stack_executable: bool = False
    """Stack is executable or not."""

    pie: bool = False
    """Position-Independent Executable (PIE) enabled or not."""

    shstk: bool = False
    """Intel CET / ARM GCS Shadow Stack (SHSTK) supported."""

    ibt: bool = False
    """Intel CET Indirect Branch Tracking (IBT) / ARM Branch Target Identification (BTI) supported."""

    fortify: bool = False
    """Glibc FORTIFY_SOURCE enabled or not."""

    mte: bool = False
    """ARM Memory Tagging Extension (MTE) supported."""

    pac: bool = False
    """ARM Pointer Authentication Codes (PAC) supported."""

    asan: bool = False
    """Binary built with Address Sanitizer (ASAN)."""

    msan: bool = False
    """Binary built with Memory Sanitizer (MSAN)."""

    ubsan: bool = False
    """Binary built with Undefined Behavior Sanitizer (UBSAN)."""

    _elf: ELF = None
    """The ELF file associated with these mitigations."""

    @property
    def bti(self) -> bool:
        """Alias for ibt, representing ARM Branch Target Identification (BTI) support."""
        return self.ibt

    @staticmethod
    def parse_elf(elf: ELF, is_debugging: bool) -> LinuxRuntimeMitigations:
        """Parse the ELF file to determine the runtime mitigations.

        Args:
            elf (ELF): The ELF file to parse.
            is_debugging (bool): Whether the process is being debugged.

        Returns:
            LinuxRuntimeMitigations: An instance with the parsed mitigations.
        """
        relro = LinuxRuntimeMitigations._parse_relro(elf)

        # Symbols require starting a process in libdebug, so I'm just gonna look for the string
        # Yes, it's enogh for the mitigation, albeit not ideal
        strings_of_interest = []

        # .plt symbols will not be in the list of symbols, so we should use a heuristic lookup
        strings_of_interest = quick_sym_heuristic_lookup(elf.path, "_chk")

        stack_guard = "__stack_chk_fail" in strings_of_interest

        nx = LinuxRuntimeMitigations._parse_nx(elf)

        stack_executable = LinuxRuntimeMitigations._parse_stack_executable(elf)

        # FORTIFY_SOURCE
        # adds symbols like __memcpy_chk, __sprintf_chk
        fortify = any(candidate.startswith("__") and candidate.endswith("_chk") for candidate in strings_of_interest)

        pie = elf.is_pie

        shstk = LinuxRuntimeMitigations._parse_shadowstack(elf)

        ibt = LinuxRuntimeMitigations._parse_ibt(elf)

        if is_debugging:
            asan = any(sym.name.startswith("__asan_") for sym in elf.symbols)
            msan = any(sym.name.startswith("__msan_") for sym in elf.symbols)
            ubsan = any(sym.name.startswith("__ubsan_") for sym in elf.symbols)
        else:
            strings_of_interest = quick_sym_heuristic_lookup(elf.path, "san_")
            asan = any("__asan_" in candidate for candidate in strings_of_interest)
            msan = any("__msan_" in candidate for candidate in strings_of_interest)
            ubsan = any("__ubsan_" in candidate for candidate in strings_of_interest)

        mte = LinuxRuntimeMitigations._parse_mte(elf)
        pac = LinuxRuntimeMitigations._parse_pac(elf)

        return LinuxRuntimeMitigations(
            relro=relro,
            stack_guard=stack_guard,
            nx=nx,
            stack_executable=stack_executable,
            pie=pie,
            shstk=shstk,
            ibt=ibt,
            fortify=fortify,
            asan=asan,
            msan=msan,
            ubsan=ubsan,
            mte=mte,
            pac=pac,
            _elf=elf,
        )

    @staticmethod
    def _parse_relro(elf: ELF) -> RelroStatus:
        """Parse the RELRO status from the ELF file.

        Args:
            elf (ELF): The ELF file to parse.

        Returns:
            RelroStatus: The RELRO status.
        """
        if not any(ph.header_type == "GNU_RELRO" for ph in elf.program_headers):
            return RelroStatus.NONE

        # -- BIND_NOW as a dedicated dynamic tag? --

        bind_now = elf.dynamic_sections.filter("BIND_NOW")

        if len(bind_now) > 0:
            return RelroStatus.FULL

        # -- BIND_NOW in dynamic flags? --
        try:
            flags = elf.dynamic_sections.filter("BIND_NOW")[0]
        except IndexError:
            flags = ""

        if "BIND_NOW" in flags:
            return RelroStatus.FULL

        # -- NOW in dynamic flags_1? --
        try:
            flags_1 = elf.dynamic_sections.filter("FLAGS_1")[0].value
        except IndexError:
            flags_1 = ""

        if "NOW" in flags_1:
            return RelroStatus.FULL

        return RelroStatus.PARTIAL

    @staticmethod
    def _parse_nx(elf: ELF) -> bool:
        """Parse the NX (Non-Executable) status from the ELF file.

        Args:
            elf (ELF): The ELF file to parse.

        Returns:
            bool: True if NX is enabled, False otherwise.
        """
        exec_bit = None
        for ph in elf.program_headers.filter("GNU_STACK"):
            exec_bit = "X" in ph.flags

        non_exec = exec_bit is False
        missing = exec_bit is None

        if elf.arch in ["i386", "aarch64"]:
            if non_exec:
                return True
            elif missing:
                return False
            return None
        elif elf.arch == "amd64":
            return True if non_exec else None

        return True

    @staticmethod
    def _parse_stack_executable(elf: ELF) -> bool:
        """Parse if the stack is executable from the ELF file.

        Args:
            elf (ELF): The ELF file to parse.

        Returns:
            bool: True if the stack is executable, False otherwise.
        """
        for ph in elf.program_headers.filter("GNU_STACK"):
            return "X" in ph.flags
        return True

    @staticmethod
    def _parse_shadowstack(elf: ELF) -> bool:
        """Parse if the binary was built with Intel CET Shadow Stack (SHSTK) or ARM Guarded Control Stack (GCS).

        Args:
            elf (ELF): The ELF file to parse.

        Returns:
            bool: True if SHSTK is supported, False otherwise.
        """
        if elf.arch in ["i386", "amd64"]:
            x86_features = elf.gnu_properties.filter("X86_FEATURE_1_AND")

            return len(x86_features) > 0 and "SHSTK" in x86_features[0].value
        elif elf.arch == "aarch64":
            aarch64_features = elf.gnu_properties.filter("AARCH64_FEATURE_1_AND")

            return len(aarch64_features) > 0 and "GCS" in aarch64_features[0].value

        return False

    @staticmethod
    def _parse_ibt(elf: ELF) -> bool:
        """Parse if the binary was built with Intel CET Indirect Branch Tracking (IBT) / ARM Branch Target Identification (BTI).

        Args:
            elf (ELF): The ELF file to parse.

        Returns:
            bool: True if IBT is supported, False otherwise.
        """
        if elf.arch in ["i386", "amd64"]:
            x86_features = elf.gnu_properties.filter("X86_FEATURE_1_AND")

            return len(x86_features) > 0 and "IBT" in x86_features[0].value
        elif elf.arch == "aarch64":
            aarch64_features = elf.gnu_properties.filter("AARCH64_FEATURE_1_AND")

            return len(aarch64_features) > 0 and "BTI" in aarch64_features[0].value

        return False

    @staticmethod
    def _parse_mte(elf: ELF) -> bool:
        """Parse if the binary was built with ARM Memory Tagging Extension (MTE).

        Args:
            elf (ELF): The ELF file to parse.

        Returns:
            bool: True if MTE is supported, False otherwise.
        """
        if elf.arch != "aarch64":
            return False

        program_headers = elf.program_headers.filter("AARCH64_MEMTAG_MTE")

        return len(program_headers) > 0

    @staticmethod
    def _parse_pac(elf: ELF) -> bool:
        """Parse if the binary was built with ARM Pointer Authentication Codes (PAC).

        Args:
            elf (ELF): The ELF file to parse.

        Returns:
            bool: True if PAC is supported, False otherwise.
        """
        if elf.arch != "aarch64":
            return False

        aarch64_features = elf.gnu_properties.filter("AARCH64_FEATURE_1_AND")

        return len(aarch64_features) > 0 and "PAC" in aarch64_features[0].value
