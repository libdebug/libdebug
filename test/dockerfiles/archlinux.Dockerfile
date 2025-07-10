FROM archlinux:latest

RUN pacman -Syu --noconfirm && pacman -S --noconfirm python python-pip pypy3 libelf libdwarf gcc make debuginfod cmake pkg-config

WORKDIR /test

# Arch Linux forces venvs
RUN python -m venv venv_python
RUN venv_python/bin/python -m pip install -U pip pwntools requests capstone objgraph

RUN pypy3 -m venv venv_pypy
RUN venv_pypy/bin/python -m pip install -U pip pwntools requests capstone objgraph

COPY . .

COPY test/dockerfiles/run_tests.sh /test/test/run_tests.sh

RUN venv_python/bin/python -m pip install --compile .
RUN venv_pypy/bin/python -m pip install --compile .

WORKDIR /test/test

ENTRYPOINT [ "/test/test/run_tests.sh" ]
