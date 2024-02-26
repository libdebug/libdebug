FROM ubuntu:latest

RUN apt-get update && apt-get install -y libssl-dev pkg-config curl python3 python3-dev python3-pip pypy3 pypy3-dev libdwarf-dev libelf-dev linux-headers-generic libc6-dbg
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /test

RUN python3 -m pip install -U pip
RUN pypy3 -m pip install -U pip

RUN python3 -m pip install pwntools
RUN pypy3 -m pip install pwntools

COPY . .

COPY test/dockerfiles/run_tests.sh /test/test/run_tests.sh

RUN python3 -m pip install .
RUN pypy3 -m pip install .

WORKDIR /test/test

ENTRYPOINT [ "/test/test/run_tests.sh" ]