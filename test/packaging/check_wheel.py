"""Validate the distributable, without importing anything from the checkout."""

import argparse
import ast
import base64
import csv
import hashlib
import io
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZipFile

MODULES = (
    "libdebug/ptrace/native/libdebug_ptrace_binding",
    "libdebug/native/libdebug_linux_binding",
    "libdebug/native/libdebug_debug_sym_parser",
)


def check_wheel(path: Path, mode: str) -> None:
    with ZipFile(path) as wheel:
        names = wheel.namelist()
        assert len(names) == len(set(names)), "Duplicate wheel members"
        metadata_name = next(n for n in names if n.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(wheel.read(metadata_name))
        requirements = metadata.get_all("Requires-Dist", [])
        backend = [r for r in requirements if r.startswith("nanobind-backend")]
        assert bool(backend) == (mode == "split"), requirements
        if backend:
            assert backend == ["nanobind-backend>=1.0"], backend
        assert not any(r.startswith("nanobind ") or r.startswith("nanobind<") for r in requirements)
        wheel_name = metadata_name.replace("METADATA", "WHEEL")
        tags = BytesParser().parsebytes(wheel.read(wheel_name)).get_all("Tag", [])
        expected = ("cp310-abi3-",) if mode == "split" else (
            "cp310-cp310-", "cp311-cp311-", "cp312-abi3-",
        )
        assert tags and all(tag.startswith(expected) for tag in tags), tags
        assert "libdebug/py.typed" in names
        stubs = {n for n in names if n.endswith(".pyi")}
        assert stubs == {m + ".pyi" for m in MODULES}, stubs
        for module in MODULES:
            extensions = [n for n in names if n.startswith(module + ".") and n.endswith(".so")]
            assert len(extensions) == 1, extensions
            if any("-abi3-" in tag for tag in tags):
                assert extensions[0] == module + ".abi3.so", extensions
            stub = wheel.read(module + ".pyi").decode()
            ast.parse(stub, feature_version=(3, 10))
            assert "nanobind_backend" not in stub, module
        assert not any("nanobind_backend" in n for n in names)
        if mode == "split":
            assert not any("libstdc++" in n or "libgcc_s" in n for n in names)
        for executable in (
            "libdebug/ptrace/jumpstart/jumpstart",
            "libdebug/ptrace/native/autodetect_fpregs_layout",
        ):
            assert wheel.getinfo(executable).external_attr >> 16 & 0o111, executable
        record_name = metadata_name.replace("METADATA", "RECORD")
        records = list(csv.reader(io.StringIO(wheel.read(record_name).decode())))
        assert {r[0] for r in records} == {n for n in names if not n.endswith("/")}
        for name, digest, size in records:
            if name == record_name:
                continue
            data = wheel.read(name)
            assert int(size) == len(data), name
            algorithm, encoded = digest.split("=", 1)
            actual = base64.urlsafe_b64encode(hashlib.new(algorithm, data).digest()).rstrip(b"=")
            assert actual.decode() == encoded, name
    print(f"{path.name}: {mode} artifact verified; sha256={hashlib.sha256(path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", type=Path, nargs="+")
    parser.add_argument("--mode", choices=("split", "linked"), required=True)
    args = parser.parse_args()
    for path in args.wheels:
        check_wheel(path, args.mode)
