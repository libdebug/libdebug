FROM ubuntu:oracular-20240527

RUN apt-get update && apt-get install -y python3 python3-dev python3-pip python3-venv libdwarf-dev libelf-dev libiberty-dev linux-headers-generic libc6-dbg

RUN python3 -m venv venv

COPY . /libdebug

WORKDIR /libdebug
RUN /venv/bin/python -m pip install --compile /libdebug

ENTRYPOINT [ "/venv/bin/python", "/libdebug/test/benchmark/slow_benchmark.py"]