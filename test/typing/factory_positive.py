from typing import assert_type

from libdebug import Debugger, DockerDebugger, DockerDebuggerMixin, debugger


class Plugin(Debugger):
    def plugin_method(self) -> int:
        return 1


class DockerPlugin(DockerDebuggerMixin, Plugin):
    pass


assert_type(debugger(), Debugger)
assert_type(debugger("/bin/true", cls=Plugin), Plugin)
assert_type(debugger("/bin/true", cls=DockerDebugger, container="fixture"), DockerDebugger)
assert_type(debugger("/bin/true", cls=DockerPlugin, container="fixture"), DockerPlugin)
assert_type(debugger("/bin/true", cls=DockerPlugin, container="fixture").plugin_method(), int)

assert_type(debugger(stop_on_exec=True, preserve_event_hooks_on_exec=False), Debugger)
assert_type(debugger("/bin/true", cls=Plugin, stop_on_fork=True, stop_on_clone=True), Plugin)
assert_type(debugger("/bin/true", cls=DockerPlugin, container="fixture", stop_on_exec=True,
                     preserve_event_hooks_on_exec=False), DockerPlugin)
