from libdebug import Debugger, debugger


class HostPlugin(Debugger):
    pass


# Each invalid call must produce diagnostics, with no blanket type ignores.
debugger("/bin/true", container="fixture")  # expected-error
debugger("/bin/true", cls=HostPlugin, container="fixture")  # expected-error
debugger("/bin/true", runtime="docker")  # expected-error
debugger("/bin/true", cls=str)  # expected-error
