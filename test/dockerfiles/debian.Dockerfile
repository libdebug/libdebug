FROM debian:latest

RUN apt-get update && apt-get install -y python3 python3-dev python3-pip python3-venv libdwarf-dev libdwarf-dev libelf-dev linux-headers-generic libc6-dbg

WORKDIR /test

# Debian forces venvs
RUN python3 -m venv venv
RUN venv/bin/python -m pip install -U pip
RUN venv/bin/python -m pip install pwntools

COPY . .

COPY test/dockerfiles/run_tests.sh /test/test/run_tests.sh

RUN venv/bin/python -m pip install .

WORKDIR /test/test

ENTRYPOINT [ "/test/test/run_tests.sh" ]