#!/usr/bin/env python3
import re
import subprocess
import sys


def get_os_vars():
    d = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    # Simple unquoting for VAR="value" or VAR='value'
                    d[k.strip()] = v.strip().strip("'\"")
            return d
    except FileNotFoundError:
        sys.exit("Error: /etc/os-release not found.")
    except Exception as e:
        sys.exit(f"Error: Cannot read /etc/os-release: {e}")


info = get_os_vars()
ID, VERSION_ID = info.get("ID"), info.get("VERSION_ID")

script = None
if ID == "centos" and VERSION_ID == "7":
    script = "cmake/prepare_for_wheel_distrib_centos.sh"
elif ID == "almalinux" and VERSION_ID and re.match(r"^8(\..*)?$", VERSION_ID):
    script = "cmake/prepare_for_wheel_distrib_almalinux.sh"
elif ID == "alpine":
    script = "cmake/prepare_for_wheel_distrib_alpine.sh"

if not script:
    sys.exit(f"Error: Unsupported OS: ID='{ID}', VERSION_ID='{VERSION_ID}'.")

print(f"Executing {script}...")
try:
    # Execute script; its stdout/stderr will be inherited (go to terminal)
    # check=True will raise an error if the script fails.
    subprocess.run([script], check=True)
except (FileNotFoundError, PermissionError, subprocess.CalledProcessError) as e:
    # The 'e' object for CalledProcessError contains command and return code.
    # Any output from the script itself would have already gone to the terminal.
    sys.exit(f"Error: {script} execution failed: {e}")
