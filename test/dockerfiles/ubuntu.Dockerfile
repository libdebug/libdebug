FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3 python3-dev python3-pip libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg libc6-i386

WORKDIR /test

RUN python3 -m pip install -U pip pwntools requests capstone pyelftools

COPY . .

COPY test/dockerfiles/run_tests.sh /test/test/run_tests.sh

RUN python3 -m pip install --compile .

WORKDIR /test/test

ENTRYPOINT [ "/test/test/run_tests.sh" ]
