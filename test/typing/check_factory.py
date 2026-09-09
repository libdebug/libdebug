"""Run with Python; requires pyright on PATH. Unexpected diagnostics remain failures."""

import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent
files = [root / "factory_positive.py", root / "factory_negative.py"]
result = subprocess.run(["pyright", "--outputjson", *map(str, files)], capture_output=True, text=True)
report = json.loads(result.stdout)
expected = {
    (str(path), number)
    for path in files
    for number, line in enumerate(path.read_text().splitlines())
    if "# expected-error" in line
}
seen = set()
for diagnostic in report["generalDiagnostics"]:
    location = (diagnostic["file"], diagnostic["range"]["start"]["line"])
    if location not in expected or diagnostic["severity"] != "error":
        raise SystemExit(json.dumps(diagnostic, indent=2))
    seen.add(location)
if expected != seen:
    raise SystemExit(f"Missing expected diagnostics: {expected - seen}")
if result.returncode not in (0, 1):
    raise SystemExit(result.stderr)
print("Factory typing checks passed (exact subclass inference and invalid calls).")
