import sys
import string

sys.path.insert(0, '../../')

from libdebug import debugger

flag = ''
counter = 1
new_counter = 0

def brutinino(d,b):
    global new_counter

    new_counter = b.hit_count


while True:

    for c in string.printable:
        d = debugger('./brutino')

        r = d.start()

        d.b(0x40120f, brutinino, hardware_assisted=True)

        d.cont()
        
        r.sendlineafter(b'chars\n', (flag+c).encode())
        r.recvline()

        if new_counter > counter:
            flag += c
            print(flag)
            print(new_counter)
            counter = new_counter
            d.kill()
            break

        d.kill()
