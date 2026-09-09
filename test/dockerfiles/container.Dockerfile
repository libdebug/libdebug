FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
RUN if [ "$(dpkg --print-architecture)" = amd64 ]; then \
        apt-get update && apt-get install -y --no-install-recommends gcc-multilib libc6-dev-i386 \
        && rm -rf /var/lib/apt/lists/*; fi
COPY srcs/container_input.c srcs/container_library.c /src/
RUN mkdir /app \
    && gcc -g -O0 -shared -fPIC /src/container_library.c -o /app/libcontainer_fixture.so \
    && gcc -g -O0 /src/container_input.c -L/app -lcontainer_fixture -Wl,-rpath,/app -o /app/program \
    && ln -s /app/program /app/program-link \
    && cp /app/program /app/program-other \
    && cp /app/program /app/not-executable && chmod -x /app/not-executable
ENV LIBDEBUG_FIXTURE=from-container
CMD ["sleep", "infinity"]
RUN if [ "$(dpkg --print-architecture)" = amd64 ]; then \
        gcc -m32 -g -O0 -shared -fPIC /src/container_library.c -o /app/libcontainer_fixture32.so \
        && gcc -m32 -g -O0 /src/container_input.c -L/app -lcontainer_fixture32 -Wl,-rpath,/app -o /app/program-i386; fi
