---
icon: material/call-missed
search:
    boost: 1
---
# :material-call-missed: Execution Hijacking Example - TRX CTF 2025

This code example shows how to hijack the exection flow of the program to retrieve the state of a Sudoku game and solve it with Z3. This is a challenge from the TRX CTF 2025. The full writeup, written by Luca Padalino (padawan), can be found [here](https://towerofhanoi.it/writeups/2025-03-14-sudo-kurl/).

The following is the initial state of the Sudoku board retrieved by the script:

```
initial_board = [
    0,0,0,21,0,11,0,0,3,24,9,20,23,0,7,22,0,5,18,0,15,2,16,13,0,
    24,4,0,20,15,0,0,5,0,16,2,25,22,0,17,6,21,0,14,0,8,10,1,19,18,
    0,0,10,0,5,0,21,19,22,0,3,13,1,16,0,15,4,7,23,24,12,0,14,0,0,
    0,0,13,6,12,14,4,1,0,0,24,18,19,5,0,0,17,0,0,0,7,22,0,9,21,
    0,23,19,7,0,0,6,0,0,20,15,4,0,21,0,0,0,0,16,10,24,3,0,17,5,
    12,15,21,0,0,0,16,6,18,5,7,0,17,3,9,14,0,4,24,22,13,0,0,0,0,
    14,10,11,2,24,1,25,22,20,0,0,23,6,19,0,13,5,8,12,0,17,0,7,15,9,
    0,0,0,0,1,24,0,3,15,10,20,8,5,0,25,9,16,19,21,0,2,6,0,12,14,
    0,0,5,0,3,0,23,14,8,0,0,2,15,0,12,0,7,1,17,6,22,21,4,0,19,
    13,0,0,4,20,0,0,0,17,0,11,16,0,0,22,0,10,18,15,23,0,25,8,1,3,
    20,25,7,22,0,23,0,10,1,0,0,0,0,13,4,21,0,6,19,0,3,9,15,8,0,
    1,24,0,0,0,4,0,20,13,0,8,0,3,0,19,16,2,12,9,5,0,14,10,25,22,
    0,0,0,0,0,0,0,9,24,0,25,6,0,2,16,4,8,10,0,17,18,7,21,0,1,
    0,8,0,10,14,16,3,25,6,0,0,7,18,9,11,0,13,0,20,0,19,24,5,0,17,
    17,3,0,15,9,5,0,0,11,0,0,21,0,0,23,7,0,22,0,0,20,13,12,4,6,
    15,0,20,11,21,10,0,0,5,22,16,0,0,8,3,24,0,13,2,19,0,0,0,0,0,
    0,13,8,0,19,17,0,0,0,0,0,12,7,24,6,0,15,23,22,4,14,5,9,0,0,
    9,1,23,14,4,0,24,0,7,8,19,0,2,0,13,17,3,20,5,0,0,15,0,16,10,
    10,0,2,12,0,13,18,15,0,0,17,5,0,20,21,8,1,16,0,7,0,19,0,11,0,
    7,5,17,24,16,20,2,11,19,3,23,0,4,15,1,18,14,0,10,0,0,8,13,21,12,
    0,20,9,0,7,15,22,17,10,0,12,19,0,0,24,25,0,14,4,8,16,18,2,0,0,
    19,2,24,8,0,0,20,7,4,0,0,0,9,0,15,5,0,21,11,16,1,0,0,14,25,
    0,0,25,1,0,8,5,23,14,6,4,17,16,0,2,0,20,0,13,9,10,12,24,7,15,
    0,0,14,0,0,0,0,0,0,2,6,10,13,0,5,12,0,24,0,0,9,11,0,3,8,
    6,0,15,0,13,0,0,24,0,9,1,0,8,25,0,10,18,17,0,2,0,4,19,0,23
]
```

The solution script uses **libdebug** to force the binary to print the state of the board. This state is then parsed and used to create a Z3 model that solves the Sudoku. The solution is then sent back to the binary to solve the game.

```python
from z3 import *
from libdebug import debugger

d = debugger("./chall")
pipe = d.run()

# 0) Hijack the instruction pointer to the displayBoard function
bp = d.breakpoint(f"play()+{str(hex(38))}", file="binary", hardware=True)
while not d.dead:
    d.cont()
    d.wait()

    if bp.hit_on(d.threads[0]):
        d.step()
        print("Hit on play+38")
        d.regs.rip = d.maps[0].base + 0x2469

# 1) Get information from the board
pipe.recvline(numlines=4)
initial_board = pipe.recvline(25).decode().strip().split(" ")
initial_board = [int(x) if x != "." else 0 for x in initial_board]

BOARD_SIZE = 25
BOARD_STEP = 5

# 2) Solve using Z3
s = Solver()

# 2.1) Create board
board = [[Int(f"board_{i}_{j}") for i in range(25)] for j in range(25)]
# 2.2) Add constraints
for i in range(BOARD_SIZE):
    for j in range(25):
        # 2.2.1) All the numbers must be between 1 and 25
        s.add(board[i][j] >= 1, board[i][j] <= 25)
        # 2.2.2) If the number is already given, it must be the same     
        if initial_board[i*25+j] != 0:
            s.add(board[i][j] == initial_board[i*25+j])
    # 2.2.3) All the numbers in the row must be different
    s.add(Distinct(board[i]))
    # 2.2.4) All the numbers in the column must be different
    s.add(Distinct([board[j][i] for j in range(BOARD_SIZE)]))

# 2.2.5) All the numbers in the 5x5 blocks must be different
for i in range(0, BOARD_SIZE, BOARD_STEP):
    for j in range(0, BOARD_SIZE, BOARD_STEP):
        block = [board[i+k][j+l] for k in range(BOARD_STEP) for l in range(BOARD_STEP)]
        s.add(Distinct(block))

# 2.3) Check if the board is solvable
if s.check() == sat:
    m = s.model()

    # 3) Solve the game
    pipe = d.run()
    d.cont()
    pipe.recvuntil("deploy.\n")
    
    # Send found solution
    for i in range(BOARD_SIZE):
        for j in range(BOARD_SIZE):
            if initial_board[i*25+j] == 0:
                pipe.recvuntil(": ")
                pipe.sendline(f"{i+1}")
                pipe.recvuntil(": ")
                pipe.sendline(f"{j+1}")
                pipe.recvuntil(": ")
                pipe.sendline(str(m[board[i][j]]))
                print(f"Row {i+1} - Col {j+1}: {m[board[i][j]]}")

    pipe.recvuntil(": ")
    pipe.sendline(f"0")

    # Receive final messages and the flag
    print(pipe.recvline().decode())
    print(pipe.recvline().decode())
    print(pipe.recvline().decode())
    print(pipe.recvline().decode())
    print(pipe.recvline().decode())
else:
    print("No solution found")

d.terminate()
```