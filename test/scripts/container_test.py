#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
import uuid
import platform

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from libdebug import Debugger, DockerDebugger, DockerDebuggerMixin, EventType, debugger, libcontext
from libdebug.debugger.mixins.base import EngineBoundMixin
from libdebug.utils.container import ContainerError
from utils.container_fixture_utils import build_container_fixture, docker_command


class FixturePluginMixin(EngineBoundMixin):
    def __init__(self):
        super().__init__()
        self.plugin_initialized = True

    def fixture_marker(self):
        return int.from_bytes(self.memory[self.resolve_symbol("marker"), 4], "little")


class PluginDebugger(Debugger, FixturePluginMixin):
    pass


class CustomDockerDebugger(DockerDebuggerMixin, PluginDebugger):
    pass


class ContainerTest(TestCase):
    docker_integration = True

    @classmethod
    def setUpClass(cls):
        previous_sym_lvl = libcontext.sym_lvl
        libcontext.sym_lvl = 3
        cls.addClassCleanup(setattr, libcontext, "sym_lvl", previous_sym_lvl)
        cls.image = f"libdebug-container-test:{uuid.uuid4().hex}"
        build_container_fixture(cls.image)
        cls.addClassCleanup(docker_command, "image", "rm", cls.image)

    def setUp(self):
        self.container = f"libdebug-container-test-{uuid.uuid4().hex}"
        docker_command(
            "run", "-d", "--name", self.container,
            "--label", "org.libdebug.test=docker",
            "--cap-add=SYS_PTRACE", "--security-opt", "apparmor=unconfined", self.image,
        )
        self.addCleanup(docker_command, "rm", "-f", self.container)
        self.cache = TemporaryDirectory()
        self.addCleanup(self.cache.cleanup)

    def make_debugger(self, argv="/app/program", **kwargs):
        kwargs.setdefault("cls", DockerDebugger)
        kwargs.setdefault("container", self.container)
        kwargs.setdefault("runtime", "docker")
        kwargs.setdefault("container_cache_path", self.cache.name)
        d = debugger(argv, **kwargs)
        self.addCleanup(d.terminate)
        return d

    def finish(self, d, pipe, expected_path="/app/program", argument="none", env="from-container", extra="unset"):
        d.cont()
        self.assertEqual(pipe.recvline(timeout=5), f"argv0={expected_path}".encode())
        self.assertEqual(pipe.recvline(timeout=5), f"arg={argument}".encode())
        self.assertEqual(pipe.recvline(timeout=5), f"env={env}".encode())
        self.assertEqual(pipe.recvline(timeout=5), f"extra={extra}".encode())
        self.assertEqual(pipe.recvline(timeout=5), b"value=73")
        self.assertEqual(pipe.recverrline(timeout=5), b"stderr-ready")
        pipe.sendline(b"real docker IO")
        self.assertEqual(pipe.recvline(timeout=5), b"echo=real docker IO")
        d.wait()
        self.assertTrue(d.dead)
        self.assertEqual(d.exit_code, 0)

    def test_launch_breakpoints_registers_memory_and_symbols(self):
        d = self.make_debugger(cls=CustomDockerDebugger)
        self.assertIs(type(d), CustomDockerDebugger)
        self.assertTrue(d.plugin_initialized)
        self.assertEqual(d.path, "/app/program")
        pipe = d.run()
        bp = d.bp("checkpoint")
        d.cont()
        self.assertTrue(bp.hit_on(d))
        self.assertEqual(d.instruction_pointer, bp.address)
        self.assertEqual(d.fixture_marker(), 42)
        d.step()
        self.assertNotEqual(d.instruction_pointer, bp.address)
        bp.disable()
        library_bp = d.bp("container_value", file="libcontainer_fixture.so")
        self.assertGreater(library_bp.address, 0)
        symbols = d.symbols.filter("container_value")
        self.assertTrue(symbols)
        self.assertTrue(any(symbol.backing_file == "/app/libcontainer_fixture.so" for symbol in symbols))
        library_bp.disable()
        self.finish(d, pipe)

    def test_symlink_and_persistent_cache(self):
        d = self.make_debugger("/app/program-link")
        self.finish(d, d.run(), expected_path="/app/program-link")
        cache_files = {path: path.stat().st_mtime_ns for path in Path(self.cache.name).iterdir()}
        self.assertTrue(cache_files)
        second = self.make_debugger("/app/program-link")
        self.finish(second, second.run(), expected_path="/app/program-link")
        self.assertEqual(cache_files, {path: path.stat().st_mtime_ns for path in Path(self.cache.name).iterdir()})

    def test_environment(self):
        for env, expected, extra in ((None, "from-container", "unset"), ({}, "unset", "unset"),
                                     ({"LIBDEBUG_EXTRA": "explicit"}, "unset", "explicit")):
            with self.subTest(env=env):
                d = self.make_debugger(["/app/program", "argument with spaces"], env=env)
                self.finish(d, d.run(), argument="argument with spaces", env=expected, extra=extra)

    def test_rerun_and_path_changes(self):
        d = self.make_debugger()
        self.finish(d, d.run())
        self.finish(d, d.run())
        d.kill()
        d.argv[0] = "/app/program-other"
        self.assertEqual(d.path, "/app/program-other")
        self.finish(d, d.run(), expected_path="/app/program-other")
        d.kill()
        d.path = "/app/program"
        d.argv = ["/app/program", "changed"]
        self.finish(d, d.run(), argument="changed")

    def test_entrypoint_disabled(self):
        d = self.make_debugger(continue_to_binary_entrypoint=False)
        pipe = d.run()
        bp = d.bp("checkpoint")
        d.cont()
        self.assertTrue(bp.hit_on(d))
        bp.disable()
        self.finish(d, pipe)

    def test_kill_and_terminate(self):
        d = self.make_debugger()
        d.run()
        pid = d.pid
        d.kill()
        self.assertFalse(Path(f"/proc/{pid}").exists())
        d.run()
        pid = d.pid
        d.terminate()
        self.assertFalse(Path(f"/proc/{pid}").exists())

    def test_detach_leaves_target_alive(self):
        d = self.make_debugger()
        pipe = d.run()
        pid = d.pid
        d.detach()
        os.kill(pid, 0)
        self.assertEqual(pipe.recvline(timeout=5), b"argv0=/app/program")
        d.terminate()
        os.kill(pid, 0)
        pipe.sendline(b"detached")
        pipe.recvuntil(b"echo=detached\n", timeout=5)
        pipe.close()

    def test_follow_child_preserves_plugin_and_configuration(self):
        d = self.make_debugger(["/app/program", "fork"], cls=CustomDockerDebugger, env={"LIBDEBUG_EXTRA": "parent"})
        pipe = d.run()
        bp = d.bp("checkpoint")
        d.cont()
        self.assertTrue(bp.hit_on(d))
        self.assertEqual(len(d.children), 1)
        child = d.children[0]
        self.addCleanup(child.terminate)
        self.assertIs(type(child), CustomDockerDebugger)
        self.assertTrue(child.plugin_initialized)
        self.assertEqual(child.path, "/app/program")
        child_bp = child.bp("checkpoint")
        child.cont()
        self.assertTrue(child_bp.hit_on(child))
        self.assertEqual(child.fixture_marker(), 42)
        child_bp.disable()
        bp.disable()
        child.cont()
        d.cont()
        child.wait()
        d.wait()
        self.assertEqual({pipe.recvline(timeout=5), pipe.recvline(timeout=5)}, {b"child", b"parent"})
        child.kill()
        child.env["LIBDEBUG_EXTRA"] = "child"
        child.argv.append("child-only")
        self.assertEqual(d.env["LIBDEBUG_EXTRA"], "parent")
        self.assertEqual(list(d.argv), ["/app/program", "fork"])

    def test_invalid_factory_arguments(self):
        for cls in (Debugger, PluginDebugger):
            with self.assertRaisesRegex(TypeError, "DockerDebuggerMixin"):
                self.make_debugger(cls=cls)
        with self.assertRaisesRegex(ValueError, "container"):
            debugger("/app/program", cls=DockerDebugger)
        for aslr in (True, False):
            with self.assertRaisesRegex(ValueError, "aslr"):
                self.make_debugger(aslr=aslr)
        with self.assertRaisesRegex(ValueError, r"argv\[0\]"):
            self.make_debugger(["custom-name"], path="/app/program")

    def test_missing_binary_and_stopped_container(self):
        with self.assertRaises(ContainerError):
            self.make_debugger("/app/does-not-exist")
        self.assertFalse(list(Path(self.cache.name).glob(".libdebug-copy-*")))
        docker_command("stop", "-t", "1", self.container)
        with self.assertRaisesRegex(ContainerError, "not running"):
            self.make_debugger()

    def test_exec_failure_and_recovery(self):
        d = self.make_debugger("/app/not-executable")
        with self.assertRaisesRegex(ContainerError, "execute"):
            d.run()
        d.argv = ["/app/program"]
        self.finish(d, d.run())

    def test_unredirected_pipes_rejected(self):
        d = self.make_debugger()
        with self.assertRaises(NotImplementedError):
            d.run(redirect_pipes=False)

    def test_exact_environment_and_target_exec(self):
        for env in (None, {}, {"PWD": "/explicit pwd", "LIBDEBUG_EXTRA": "with spaces", "ENV": "/missing"}):
            for entrypoint in (False, True):
                with self.subTest(env=env, entrypoint=entrypoint):
                    d = self.make_debugger(["/app/program", "environment"], env=env,
                                           continue_to_binary_entrypoint=entrypoint)
                    pipe = d.run()
                    # With entrypoint disabled we must already be past the env helper.
                    self.assertEqual(Path(f"/proc/{d.pid}/exe").readlink().name, "program")
                    d.cont()
                    d.wait()
                    raw = pipe.recvuntil(b"ENV-END\n", timeout=5).removesuffix(b"ENV-END\n")
                    actual = dict(entry.split(b"=", 1) for entry in raw.split(b"\0") if entry)
                    if env is None:
                        expected = docker_command("exec", self.container, "/bin/sh", "-c", "exec env").encode()
                        expected = dict(line.split(b"=", 1) for line in expected.splitlines())
                    else:
                        expected = {key.encode(): value.encode() for key, value in env.items()}
                    self.assertEqual(actual, expected)

    def test_unread_output_survives_exit(self):
        # Large enough to fill the host pipes, small enough to fit Docker's forwarding buffers.
        size = 128 * 1024
        d = self.make_debugger(["/app/program", "output", str(size)])
        pipe = d.run()
        interface = d._internal_debugger.debugging_interface
        client = interface._container_popen
        d.cont()
        d.wait()
        self.assertTrue(d.dead)
        output, errors = bytearray(), bytearray()
        while len(output) < size or len(errors) < size:
            if len(output) < size:
                output.extend(pipe.recv(size - len(output), timeout=10))
            if len(errors) < size:
                errors.extend(pipe.recverr(size - len(errors), timeout=10))
        self.assertEqual(output, b"O" * size)
        self.assertEqual(errors, b"E" * size)
        self.assertEqual(client.wait(timeout=10), 0)

    def test_parent_exit_preserves_child_transport(self):
        d = self.make_debugger(["/app/program", "orphan"])
        pipe = d.run()
        bp = d.bp("checkpoint")
        d.cont()
        self.assertTrue(bp.hit_on(d))
        bp.disable()
        self.assertEqual(len(d.children), 1)
        child = d.children[0]
        self.addCleanup(child.terminate)
        d.cont()
        d.wait()
        self.assertTrue(d.dead)
        child.cont()
        self.assertEqual(pipe.recvline(timeout=5), b"child-ready")
        pipe.sendline(b"finish")
        child.wait()
        self.assertEqual(pipe.recvline(timeout=5), b"child-done")

    def test_i386_target(self):
        if platform.machine() != "x86_64":
            self.skipTest("i386 targets require an amd64 host")
        d = self.make_debugger("/app/program-i386")
        self.assertEqual(d.arch, "i386")
        pipe = d.run()
        bp = d.bp("checkpoint")
        d.cont()
        self.assertTrue(bp.hit_on(d))
        bp.disable()
        self.finish(d, pipe, expected_path="/app/program-i386")

    def test_exec_preserves_plugin_and_refreshes_image(self):
        targets = [("/app/program-other", libcontext.platform)]
        if platform.machine() == "x86_64":
            targets.append(("/app/program-i386", "i386"))
        for target, arch in targets:
            with self.subTest(target=target):
                d = self.make_debugger(["/bin/sh", "-c", f"exec {target}"], cls=CustomDockerDebugger,
                                       stop_on_exec=True, preserve_event_hooks_on_exec=False)
                pipe = d.run()
                survivor = d.threads[0]
                installed = []

                def on_exec(thread, hook):
                    self.assertEqual(d.arch, arch)
                    self.assertIs(thread, survivor)
                    self.assertTrue(d.plugin_initialized)
                    self.assertEqual(d.fixture_marker(), 42)
                    installed.append(d.bp("checkpoint", file=target))

                hook = d.hook_event(EventType.EXEC, callback=on_exec)
                d.cont()
                d.wait()
                self.assertIs(type(d), CustomDockerDebugger)
                self.assertEqual(d.resume_context.event_type[d.pid], EventType.EXEC)
                self.assertEqual(hook.hit_count, 1)
                self.assertNotIn(hook, d._internal_debugger.event_hooks[EventType.EXEC])
                self.assertEqual(d.current_argv, [target])
                self.assertEqual(d.current_path, target)
                self.assertEqual(len(installed), 1)
                d.cont()
                d.wait()
                self.assertEqual(installed[0].hit_count, 1)
                installed[0].disable()
                self.finish(d, pipe, expected_path=target)
