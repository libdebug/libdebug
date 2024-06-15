#!/bin/bash

source venv/bin/activate
cd /libdebug/test/benchmark
python3 slow_benchmark.py
deactivate
exit 0
