# Debugging in Docker

Run libdebug on the Linux host and select a Docker-capable debugger class to start a target in an already-running container:

```python
from libdebug import DockerDebugger, debugger

d = debugger(
    ["/app/program", "argument"],
    cls=DockerDebugger,
    container="target",
    runtime="docker",
    container_cache_path="./container-cache",
)
try:
    pipe = d.run()
    d.breakpoint("main")
    d.cont()
    # Inspect registers, memory, and symbols as usual.
finally:
    d.terminate()
```

The host must be able to trace the target's host-visible PID. Normal Linux ptrace restrictions apply, including matching user IDs (or appropriate tracer privileges), Yama, and the container's security profile. Giving a container `SYS_PTRACE` does not grant the host debugger permission to trace a different user. The runtime must be local; a remote Docker daemon does not expose traceable processes on the debugger's host.

The container needs `/bin/sh` and, for an explicit environment dictionary, `env`. Targets must use a CPU architecture supported by the host's ptrace backend.

## Custom debugger classes

Combine `DockerDebuggerMixin` with `Debugger` or an existing plugin debugger:

```python
from libdebug import Debugger, DockerDebuggerMixin, debugger

class MyPluginDebugger(Debugger):
    def stopped_at(self):
        return self.instruction_pointer

class MyDockerDebugger(DockerDebuggerMixin, MyPluginDebugger):
    pass

d = debugger("/app/program", cls=MyDockerDebugger, container="target")
```

The factory returns the requested class, and followed child processes retain it. Container options require an explicit `cls` containing `DockerDebuggerMixin`; the default `Debugger` handles host processes. Docker-capable classes require a container name.

## Paths, environment, and lifecycle

Executable paths are absolute paths inside the container. `d.path` returns that target path. Set `d.path` or change `d.argv` while the target is not being debugged to configure a later run. The shell wrapper cannot preserve a custom `argv[0]`, so it must match the executable path whenever arguments are supplied.

With `env=None`, the target inherits the container environment. A dictionary replaces that environment; `{}` requests an empty environment. Host debugging continues to inherit the host environment by default.

libdebug reads symbols from local copies of container files and keeps container paths in maps and symbol metadata. Copies persist under `container_cache_path`, or `$XDG_CACHE_HOME/libdebug/containers` (normally `~/.cache/libdebug/containers`). Cache keys include the container identity, so replacing a container under the same name does not reuse its old files. Files modified in place within the same container require a fresh cache directory or clearing the existing cache before constructing another debugger.

`runtime` accepts a Docker-compatible executable; omission tries Docker and Podman. Explicit `aslr=True` and `aslr=False` are rejected because this launch mechanism does not control container ASLR. `run(redirect_pipes=False)` is unsupported. Detaching leaves the target running; killing or terminating an active session cleans up the target and runtime client.

## Integration tests

From the repository's `test` directory, run:

```sh
python run_suite.py docker
```

The suite builds a fixture image, starts actual containers, and traces compiled binaries. It requires Docker and host tracing permissions. Missing prerequisites and fixture failures are errors, not skips. The suite removes its own containers and image when it finishes. The normal `fast` suite remains independent of Docker.
