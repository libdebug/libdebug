FROM fedora:latest

RUN dnf -y upgrade && dnf install -y python3 python3-devel kernel-devel pypy3 pypy3-devel binutils-devel libdwarf-devel awk cmake gcc gcc-c++

WORKDIR /test

RUN python3 -m ensurepip
RUN python3 -m pip install -U pip pwntools requests capstone objgraph
RUN pypy3 -m ensurepip
RUN pypy3 -m pip install -U pip pwntools requests capstone objgraph

COPY . .

COPY test/dockerfiles/run_tests.sh /test/test/run_tests.sh

RUN python3 -m pip install --compile .
RUN pypy3 -m pip install --compile .

WORKDIR /test/test

ENTRYPOINT [ "/test/test/run_tests.sh" ]
