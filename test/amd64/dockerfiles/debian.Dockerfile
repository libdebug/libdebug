FROM debian:latest

RUN apt-get update && apt-get install -y python3 python3-dev python3-pip python3-venv libdwarf-dev libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg libc6-i386 

WORKDIR /test

# Debian forces venvs
RUN python3 -m venv venv
RUN venv/bin/python -m pip install -U pip pwntools requests capstone pyelftools

COPY . .

COPY test/amd64/dockerfiles/run_tests.sh /test/test/run_tests.sh

RUN venv/bin/python -m pip install --compile .

WORKDIR /test/test

ENTRYPOINT [ "/test/test/run_tests.sh" ]
