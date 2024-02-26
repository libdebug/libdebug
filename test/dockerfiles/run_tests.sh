#!/bin/bash

# Check if the system is Debian
if [ "$(uname -s)" = "Linux" ] && [ -f /etc/os-release ]; then
    if grep -q "^ID=debian" /etc/os-release; then
        cd /test
        source venv/bin/activate
        cd test
        echo "Running Python3 tests..."
        python3 run_suite.py
        deactivate
        exit 0
    fi
fi

# Check if the system is Arch Linux
if [ "$(uname -s)" = "Linux" ] && [ -f /etc/os-release ]; then
    if grep -q "^ID=arch" /etc/os-release; then
        cd /test
        source venv_python/bin/activate
        cd test
        echo "Running Python3 tests..."
        python3 run_suite.py
        deactivate
        source ../venv_pypy/bin/activate
        echo "Running PyPy3 tests..."
        pypy3 run_suite.py
        deactivate
        exit 0
    fi
fi

# For non-Ubuntu and non-Debian systems or non-Linux systems, run both Python3 and PyPy3 tests
cd /test/test
echo "Running Python3 tests..."
python3 run_suite.py
echo "Running PyPy3 tests..."
pypy3 run_suite.py
exit 0