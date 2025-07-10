#!/bin/sh

# Check if the system is Debian
if [ "$(uname -s)" = "Linux" ] && [ -f /etc/os-release ]; then
    if grep -q "^ID=debian" /etc/os-release; then
        cd /test
        . venv/bin/activate
        cd test
        echo "Running Python3 tests..."
        python3 run_suite.py
        deactivate
        exit 0
    fi
fi

# Check if the system is Ubuntu
if [ "$(uname -s)" = "Linux" ] && [ -f /etc/os-release ]; then
    if grep -q "^ID=ubuntu" /etc/os-release; then
        cd /test
        . venv/bin/activate
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
        . venv_python/bin/activate
        cd test
        echo "Running Python3 tests..."
        python3 run_suite.py
        deactivate
        . ../venv_pypy/bin/activate
        echo "Running PyPy3 tests..."
        pypy3 run_suite.py
        deactivate
        exit 0
    fi
fi

# Run both Python3 and PyPy3 tests
cd /test/test
echo "Running Python3 tests..."
python3 run_suite.py slow
echo "Running PyPy3 tests..."
pypy3 run_suite.py slow
echo "Running Python3 stress tests..."
python3 run_suite.py stress
echo "Running PyPy3 stress tests..."
pypy3 run_suite.py stress
exit 0
