#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2026 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

import os
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from libdebug import Debugger, DockerDebugger, DockerDebuggerMixin, debugger
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
    @classmethod
    def setUpClass(cls):
        cls.image = f"libdebug-container-test:{uuid.uuid4().hex}"
        build_container_fixture(cls.image)
        cls.addClassCleanup(docker_command, "image", "rm", cls.image)

    def setUp(self):
        self.container = f"libdebug-container-test-{uuid.uuid4().hex}"
        docker_command(
            "run", "-d", "--name", self.container,
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
