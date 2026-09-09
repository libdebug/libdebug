"""Event-driven container startup tests that do not require Docker."""

import os
import signal
import subprocess
import sys
from pathlib import Path
from threading import Event, Thread
from unittest import TestCase
from unittest.mock import Mock, patch

from libdebug import Debugger, DockerDebugger, DockerDebuggerMixin, debugger
from libdebug.debugger.mixins.configuration import ConfigurationMixin
from libdebug.utils.container import ContainerError, ContainerStartupCancelledError, read_container_pid
from utils.binary_utils import RESOLVE_EXE


class ArchitectureDebugger(Debugger):
    @ConfigurationMixin.arch.setter
    def arch(self, value):
        if getattr(self, "reject_arch", False):
            raise ValueError("plugin rejected architecture")
        self.arch_calls = getattr(self, "arch_calls", []) + [(value, self.path)]
        ConfigurationMixin.arch.fset(self, value)


class DockerArchitectureDebugger(DockerDebuggerMixin, ArchitectureDebugger):
    pass


class ContainerUnitTest(TestCase):
    def pipe(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        return read_fd, write_fd

    def test_partial_pid_reads_and_no_deadline(self):
        read_fd, write_fd = self.pipe()
        cancel_fd, _ = self.pipe()
        import select

        select_impl = select.select
        first_read = Event()

        def readable(*args):
            self.assertEqual(len(args), 3)  # No select timeout.
            first_read.set()
            return select_impl(*args)

        def writer():
            first_read.wait()
            os.write(write_fd, b"00000000")
            os.write(write_fd, b"00000123")

        worker = Thread(target=writer)
        worker.start()
        with patch("libdebug.utils.container.select.select", side_effect=readable):
            # Force each read to be partial independently of pipe write coalescing.
            original_read = os.read
            with patch(
                "libdebug.utils.container.os.read", side_effect=lambda fd, size: original_read(fd, min(size, 3))
            ):
                self.assertEqual(read_container_pid(read_fd, cancel_fd), 123)
        worker.join()

    def test_eof_and_malformed_records(self):
        for record in (b"", b"00012", b"x" * 16, b"0" * 16):
            with self.subTest(record=record):
                read_fd, write_fd = os.pipe()
                cancel_fd, _ = self.pipe()
                os.write(write_fd, record)
                os.close(write_fd)
                try:
                    with self.assertRaises(ContainerError):
                        read_container_pid(read_fd, cancel_fd)
                finally:
                    os.close(read_fd)

    def test_cancel_wakes_reader(self):
        read_fd, _ = self.pipe()
        cancel_fd, cancel_write = self.pipe()
        os.write(cancel_write, b"x")
        with self.assertRaises(ContainerStartupCancelledError):
            read_container_pid(read_fd, cancel_fd)

    def make_docker(self, cls=DockerDebugger):
        path = RESOLVE_EXE("basic_test")
        cache = Mock(container_id="fixture", copy_required_file=Mock(return_value=path))
        with patch.object(cls, "_prepare_container", return_value=("docker", 1, cache, path)):
            d = debugger("/app/program", cls=cls, container="fixture")
        self.addCleanup(d.terminate)
        return d

    def test_factory_rejects_mixin_without_debugger(self):
        with self.assertRaisesRegex(TypeError, "Debugger subclass"):
            debugger("/app/program", cls=DockerDebuggerMixin, container="fixture")

    def test_architecture_override_before_path_commit(self):
        for docker in (False, True):
            for mutation in ("path", "argv", "item"):
                with self.subTest(docker=docker, mutation=mutation):
                    if docker:
                        d = self.make_docker(DockerArchitectureDebugger)
                        new_path = "/app/other"
                    else:
                        d = debugger(RESOLVE_EXE("basic_test"), cls=ArchitectureDebugger)
                        self.addCleanup(d.terminate)
                        new_path = str(Path(RESOLVE_EXE("breakpoint_test")).resolve())
                    old_path, old_argv = d.path, list(d.argv)

                    def change():
                        if mutation == "path":
                            d.path = new_path
                        elif mutation == "argv":
                            d.argv = [new_path]
                        else:
                            d.argv[0] = new_path

                    d.reject_arch = True
                    with self.assertRaisesRegex(ValueError, "plugin rejected"):
                        change()
                    self.assertEqual(d.path, old_path)
                    self.assertEqual(list(d.argv), old_argv)
                    d.reject_arch = False
                    # Reset the list callback after its existing failure rollback behavior.
                    if mutation == "item":
                        d.argv = old_argv
                    change()
                    self.assertEqual(d.path, new_path)
                    self.assertEqual(d.arch_calls[-1][1], old_path)

    def test_startup_cancellation_reaps_client_and_closes_pipes(self):
        d = self.make_docker()
        spawned = Event()
        clients = []

        def spawn(**kwargs):
            client = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(600)"],
                stdin=kwargs["stdin_child_fd"],
                stdout=kwargs["stdout_child_fd"],
                stderr=kwargs["stderr_child_fd"],
            )
            clients.append(client)
            spawned.set()
            return client

        def interrupt():
            spawned.wait()
            os.kill(os.getpid(), signal.SIGINT)

        worker = Thread(target=interrupt)
        worker.start()
        before = len(list(Path("/proc/self/fd").iterdir()))
        with (
            patch("libdebug.debugger.docker_internal_debugger.get_container_init_pid", return_value=1),
            patch("libdebug.ptrace.docker_ptrace_interface.spawn_in_container", side_effect=spawn),
        ):
            with self.assertRaises(KeyboardInterrupt):
                d.run()
        worker.join()
        self.assertIsNotNone(clients[0].returncode)
        self.assertFalse(d._internal_debugger.is_debugging)
        self.assertEqual(before, len(list(Path("/proc/self/fd").iterdir())))

    def test_reported_pid_cleaned_on_resolution_failure(self):
        d = self.make_docker()
        clients = []

        def spawn(**kwargs):
            client = subprocess.Popen(
                [sys.executable, "-c", "import os,time; os.write(1, b'0000000000000123'); time.sleep(600)"],
                stdin=kwargs["stdin_child_fd"],
                stdout=kwargs["stdout_child_fd"],
                stderr=kwargs["stderr_child_fd"],
            )
            clients.append(client)
            return client

        with (
            patch("libdebug.debugger.docker_internal_debugger.get_container_init_pid", return_value=1),
            patch("libdebug.ptrace.docker_ptrace_interface.spawn_in_container", side_effect=spawn),
            patch(
                "libdebug.ptrace.docker_ptrace_interface.resolve_ns_pid_to_host_pid",
                side_effect=ContainerError("resolution failed"),
            ),
            patch("libdebug.ptrace.docker_ptrace_interface.kill_in_container") as kill,
        ):
            with self.assertRaisesRegex(ContainerError, "resolution failed"):
                d.run()
            kill.assert_called_once_with("docker", "fixture", 123)
        self.assertIsNotNone(clients[0].returncode)

    def test_runtime_eof_unblocks_startup_and_reaps_client(self):
        d = self.make_docker()
        clients = []

        def spawn(**kwargs):
            client = subprocess.Popen(
                [sys.executable, "-c", "pass"],
                stdin=kwargs["stdin_child_fd"],
                stdout=kwargs["stdout_child_fd"],
                stderr=kwargs["stderr_child_fd"],
            )
            clients.append(client)
            return client

        with (
            patch("libdebug.debugger.docker_internal_debugger.get_container_init_pid", return_value=1),
            patch("libdebug.ptrace.docker_ptrace_interface.spawn_in_container", side_effect=spawn),
        ):
            for _ in range(2):
                with self.assertRaisesRegex(ContainerError, "closed stdout"):
                    d.run()
                self.assertIsNotNone(clients[-1].returncode)
                self.assertFalse(d._internal_debugger.is_debugging)

    def test_real_wrapper_environment_and_exec_events_on_host(self):
        # Run the actual shell/env handshake and Docker ptrace implementation on a host child.
        # This isolates exec handling from Docker access and its privileged fixture UID.
        target = str(Path(RESOLVE_EXE("basic_test")).resolve())
        for env in (None, {}, {"PWD": "/explicit pwd", "EXTRA": "with spaces", "ENV": "/missing"}):
            with self.subTest(env=env):
                cache = Mock(container_id="fixture", copy_file=lambda path: path)
                with patch.object(DockerDebugger, "_prepare_container", return_value=("docker", 1, cache, target)):
                    d = debugger(
                        target, cls=DockerDebugger, container="fixture", env=env, continue_to_binary_entrypoint=False
                    )
                self.addCleanup(d.terminate)
                real_popen = subprocess.Popen

                def local_runtime(command, **kwargs):
                    self.assertEqual(command[:4], ["docker", "exec", "-i", "fixture"])
                    return real_popen(command[4:], **kwargs)

                with (
                    patch("libdebug.debugger.docker_internal_debugger.get_container_init_pid", return_value=1),
                    patch("libdebug.utils.container.subprocess.Popen", side_effect=local_runtime),
                    patch(
                        "libdebug.ptrace.docker_ptrace_interface.resolve_ns_pid_to_host_pid",
                        side_effect=lambda init, pid: pid,
                    ),
                ):
                    d.run()
                self.assertEqual(str(Path(f"/proc/{d.pid}/exe").readlink()), target)
                actual = Path(f"/proc/{d.pid}/environ").read_bytes()
                actual = dict(entry.split(b"=", 1) for entry in actual.split(b"\0") if entry)
                if env is not None:
                    self.assertEqual(actual, {key.encode(): value.encode() for key, value in env.items()})
                else:
                    self.assertEqual(actual[b"PATH"], os.environ["PATH"].encode())
                d.kill()

    def test_natural_reaper_preserves_unread_client_output(self):
        d = self.make_docker()
        interface = d._internal_debugger.debugging_interface
        size = 128 * 1024
        client = subprocess.Popen(
            [sys.executable, "-c", "import os; os.write(1, b'O' * 131072); os.write(2, b'E' * 131072)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(client.wait)
        self.addCleanup(client.kill)
        interface._container_popen = client
        interface._reap_container_popen()
        output, error = client.communicate(timeout=10)
        self.assertEqual(output, b"O" * size)
        self.assertEqual(error, b"E" * size)
        self.assertEqual(client.returncode, 0)

    def test_explicit_reaping_kills_before_waiting(self):
        d = self.make_docker()
        interface = d._internal_debugger.debugging_interface
        client = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        self.addCleanup(client.wait)
        self.addCleanup(client.kill)
        interface._container_popen = client
        original_wait = client.wait

        def wait(*args, **kwargs):
            self.assertFalse(args)
            self.assertFalse(kwargs)
            self.assertTrue(kill.called)
            return original_wait()

        with patch.object(client, "kill", wraps=client.kill) as kill, patch.object(client, "wait", side_effect=wait):
            interface._reap_container_popen(terminate=True)
        self.assertIsNotNone(client.returncode)

    def test_pytest_docker_selection_and_missing_runtime(self):
        # Exercise collection through pytest itself, including the explicit failure contract.
        command = [sys.executable, "-m", "pytest", "scripts/container_test.py", "-q"]
        default = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(default.returncode, 5, default.stdout + default.stderr)
        self.assertIn("deselected", default.stdout)
        env = dict(os.environ, PATH="/libdebug-no-runtime")
        explicit = subprocess.run([*command, "--docker", "-x"], capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(explicit.returncode, 1, explicit.stdout + explicit.stderr)
        self.assertIn("FileNotFoundError", explicit.stdout)
        self.assertIn("docker", explicit.stdout)

    def test_cancellation_cleans_an_already_reported_pid(self):
        d = self.make_docker()
        clients = []

        def spawn(**kwargs):
            client = subprocess.Popen(
                [sys.executable, "-c", "import os,time; os.write(1, b'0000000000000123'); time.sleep(600)"],
                stdin=kwargs["stdin_child_fd"],
                stdout=kwargs["stdout_child_fd"],
                stderr=kwargs["stderr_child_fd"],
            )
            clients.append(client)
            return client

        def cancel_after_pid(read_fd, cancel_fd):
            import select

            pid = read_container_pid(read_fd, cancel_fd)
            os.kill(os.getpid(), signal.SIGINT)
            select.select([cancel_fd], [], [])
            return pid

        with (
            patch("libdebug.debugger.docker_internal_debugger.get_container_init_pid", return_value=1),
            patch("libdebug.ptrace.docker_ptrace_interface.spawn_in_container", side_effect=spawn),
            patch("libdebug.ptrace.docker_ptrace_interface.read_container_pid", side_effect=cancel_after_pid),
            patch("libdebug.ptrace.docker_ptrace_interface.kill_in_container") as kill,
        ):
            with self.assertRaises(KeyboardInterrupt):
                d.run()
            kill.assert_called_once_with("docker", "fixture", 123)
        self.assertIsNotNone(clients[0].returncode)
