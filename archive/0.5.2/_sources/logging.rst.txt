Logging
=======
Debugging an application with the freedom of a rich API can lead to flows which are hard to unravel. To aid the user in the debugging process, libdebug provides logging, which can be enabled through `argv` parameters.

The available logging levels are:

- ``debugger``
- ``pipe``
- ``dbg``

As reported in this documentation, the `argv` parameters are *lowercase*. This choice is made to avoid conflicts with https://github.com/Gallopsled/pwntools, which intercepts uppercase arguments.

Debugger Logging
----------------
The `debugger` option displays all logs related to the debugging operations performed on the process by libdebug.

.. image:: https://github.com/libdebug/libdebug/blob/dev/media/debugger_argv.png?raw=true
   :alt: debugger argv option


Pipe Logging
------------
The `pipe` option, on the other hand, displays all logs related to interactions with the process pipe: bytes received and bytes sent.

.. image:: https://github.com/libdebug/libdebug/blob/dev/media/pipe_argv.png?raw=true
    :alt: pipe argv option

The best of both worlds
-----------------------
The `dbg` option is the combination of the `pipe` and `debugger` options. It displays all logs related to the debugging operations performed on the process by libdebug, as well as interactions with the process pipe: bytes received and bytes sent.

Temporary Logging
-----------------

Logger levels can be temporarily enabled at runtime using a `with` statement, as shown in the following example.

.. code-block:: python

    from libdebug import libcontext
    with libcontext.tmp(pipe_logger='INFO', debugger_logger='DEBUG'):
        r.sendline(b'gimme the flag')