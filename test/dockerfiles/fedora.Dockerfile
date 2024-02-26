FROM fedora:latest

RUN dnf -y upgrade && dnf install -y python3 python3-devel kernel-devel pypy3 pypy3-devel

WORKDIR /test

RUN python3 -m ensurepip
RUN python3 -m pip install -U pip
RUN pypy3 -m ensurepip
RUN pypy3 -m pip install -U pip

RUN dnf install -y libdwarf-devel

RUN python3 -m pip install pwntools
RUN pypy3 -m pip install pwntools

COPY . .

COPY test/dockerfiles/run_tests.sh /test/test/run_tests.sh

RUN python3 -m pip install .
RUN pypy3 -m pip install .

WORKDIR /test/test

ENTRYPOINT [ "/test/test/run_tests.sh" ]