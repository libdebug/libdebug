FROM archlinux:latest

RUN pacman -Syu --noconfirm && pacman -S --noconfirm python python-pip pypy3 libelf libdwarf gcc make debuginfod

WORKDIR /test

# Arch Linux forces venvs
RUN python -m venv venv_python
RUN venv_python/bin/python -m pip install -U pip
RUN venv_python/bin/python -m pip install pwntools

RUN pypy3 -m venv venv_pypy
RUN venv_pypy/bin/python -m pip install -U pip
RUN venv_pypy/bin/python -m pip install pwntools

COPY . .

COPY test/dockerfiles/run_tests.sh /test/test/run_tests.sh

RUN venv_python/bin/python -m pip install .
RUN venv_pypy/bin/python -m pip install .

WORKDIR /test/test

ENTRYPOINT [ "/test/test/run_tests.sh" ]
