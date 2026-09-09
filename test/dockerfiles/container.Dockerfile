FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY srcs/container_input.c srcs/container_library.c /src/
RUN mkdir /app \
    && gcc -g -O0 -shared -fPIC /src/container_library.c -o /app/libcontainer_fixture.so \
    && gcc -g -O0 /src/container_input.c -L/app -lcontainer_fixture -Wl,-rpath,/app -o /app/program \
    && ln -s /app/program /app/program-link \
    && cp /app/program /app/program-other \
    && cp /app/program /app/not-executable && chmod -x /app/not-executable
ENV LIBDEBUG_FIXTURE=from-container
CMD ["sleep", "infinity"]
