"""A missing split backend must produce an actionable ImportError, not abort."""

import subprocess
import sys

code = """
import sys
class BlockBackend:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('nanobind_backend'):
            raise ModuleNotFoundError('blocked for test', name=fullname)
sys.meta_path.insert(0, BlockBackend())
try:
    import libdebug.native.libdebug_debug_sym_parser
except ImportError as error:
    assert 'pip install nanobind-backend' in str(error), str(error)
else:
    raise AssertionError('A split extension imported without its backend')
"""
result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=30)
assert result.returncode == 0, result.stderr
