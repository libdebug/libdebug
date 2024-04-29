from libdebug import debugger

d = debugger("../binaries/signal_handling_test")

r = d.run()

def hookino(d, sig):
    print(f"Hooked signal {sig}")
    d.signal_number = 5

    
hook1 = d.hook_signal("SIGTRAP" , callback=hookino)
# hook1 = d.hook_signal("SIGUSR1" , callback=hookino)

d.signal_to_pass = [15, "SIGTRAP"]

print(d.signal_to_pass)

d.breakpoint('main', callback=lambda x, t: print("Breakpoint hit"))

# hook2 = d.hook_signal("SIGTERM")
# hook3 = d.hook_signal("SIGINT")
# hook4 = d.hook_signal("SIGQUIT")
# hook4 = d.hook_signal("SIGPIPE")


d.cont()

while True:
    print(r.recvline())



d.kill()