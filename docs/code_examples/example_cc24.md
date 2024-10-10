---
icon: material/shield
search:
    boost: 0.8
---
# :material-shield: CyberChallenge 2024 - Workshop
This script was used to showcase the power of **libdebug** during the Workshop at the [CyberChallenge.IT](https://cyberchallenge.it/) 2024 Finals. An explanation of the script, along with a brief introduction to **libdebug**, is available in the [official stream of the event](https://www.youtube.com/live/Ten8S50Fy7s?si=w8usHtnN5v6FWipQ&t=8253), starting from timestamp 2:17:00.

```python
from libdebug import debugger
from string import ascii_letters, digits

# Enable the escape_antidebug option to bypass the ptrace call
d = debugger("main", escape_antidebug=True)

def callback(_, __):
    # This will automatically issue a continue when the breakpoint is hit
    pass

def on_enter_nanosleep(t, _):
    # This sets every argument to NULL to make the syscall fail
    t.syscall_arg0 = 0
    t.syscall_arg1 = 0
    t.syscall_arg2 = 0
    t.syscall_arg3 = 0

alphabet = ascii_letters + digits + "_{}"

flag = b""
best_hit_count = 0

while True:
    for c in alphabet:
        r = d.run()

        # Any time we call run() we have to reset the breakpoint and syscall handler
        bp = d.breakpoint(0x13e1, hardware=True, callback=callback, file="binary")
        d.handle_syscall("clock_nanosleep", on_enter=on_enter_nanosleep)

        d.cont()

        r.sendline(flag + c.encode())

        # This makes the debugger wait for the process to terminate
        d.wait()

        response = r.recvline()

        # `run()` will automatically kill any still-running process, but it's good practice to do it manually
        d.kill()

        if b"Yeah" in response:
            # The flag is correct
            flag += c.encode()
            print(flag)
            break

        if bp.hit_count > best_hit_count:
            # We have found a new flag character
            best_hit_count = bp.hit_count
            flag += c.encode()
            print(flag)
            break

    if c == "}":
        break

print(flag)
```