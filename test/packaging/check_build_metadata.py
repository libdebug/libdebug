"""Check PEP 517 dependency selection before compiling any extension."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


class BuildMetadataTest(unittest.TestCase):
    def test_invalid_mode_is_rejected_during_metadata_preparation(self):
        result = subprocess.run(
            [sys.executable, "-c", """
from tempfile import TemporaryDirectory
from scikit_build_core import build
with TemporaryDirectory() as tmp:
    build.prepare_metadata_for_build_wheel(tmp)
"""],
            cwd=Path(__file__).resolve().parents[2],
            env={**os.environ, "LIBDEBUG_NANOBIND_SPLIT": "invalid"},
            capture_output=True, text=True, timeout=60,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LIBDEBUG_NANOBIND_SPLIT must be 0 or 1", result.stderr)

    def test_linked_and_split_dependencies(self):
        root = Path(__file__).resolve().parents[2]
        code = """
import json
import tarfile
from email.parser import BytesParser
from pathlib import Path
from tempfile import TemporaryDirectory
from scikit_build_core import build
requirements = build.get_requires_for_build_wheel()
with TemporaryDirectory() as tmp:
    result = build.prepare_metadata_for_build_wheel(tmp)
    metadata = BytesParser().parsebytes((Path(tmp) / result / 'METADATA').read_bytes())
    sdist = build.build_sdist(tmp)
    with tarfile.open(Path(tmp) / sdist) as archive:
        member = next(m for m in archive.getmembers() if m.name.endswith('/PKG-INFO'))
        source = BytesParser().parsebytes(archive.extractfile(member).read())
        assert 'Requires-Dist' in source.get_all('Dynamic', []), source
    print(json.dumps([requirements, metadata.get_all('Requires-Dist')]))
"""
        for mode in ("0", "1"):
            with self.subTest(mode=mode):
                env = {**os.environ, "LIBDEBUG_NANOBIND_SPLIT": mode}
                result = subprocess.run(
                    [sys.executable, "-c", code], cwd=root, env=env,
                    text=True, capture_output=True, timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                build, runtime = json.loads(result.stdout.splitlines()[-1])
                for requirements in (build, runtime):
                    backend = [r for r in requirements if r.startswith("nanobind-backend")]
                    self.assertEqual(backend, ["nanobind-backend>=1.0"] if mode == "1" else [])
                self.assertEqual(
                    {r for r in runtime if not r.startswith("nanobind-backend")},
                    {"psutil", "pyelftools", "prompt-toolkit", "requests", 'rich; extra == "dev"'},
                )


if __name__ == "__main__":
    unittest.main()
