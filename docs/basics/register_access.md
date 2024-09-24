---
icon: material/hexadecimal
search:
    boost: 4
---
# :material-hexadecimal: Register Access
**libdebug** offers a simple register access interface for supported architectures. Registers through the `regs` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object or the [Thread Context](../../from_pydoc/generated/state/thread_context). This includes both general-purpose and special registers, as well as the flags.

!!! INFO "Multithreading"
    In multi-threaded debugging, the `regs` attribute of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object will return the registers of the main thread.

The following is an example of how to interact with the `RAX` register in a debugger object on AMD64:

| Operation | Code Snippet                  |
| --------- | ----------------------------- |
| Reading   |   `read_value = d.regs.rax`   |
| Writing   | `d.regs.rax = read_value + 1` |

Note that the register values are read and written as Python integers. This is true for all registers except for floating point ones, which are coherent with their type. To avoid confusion, we list available registers and their types below. Related registers are available to access as well.

=== "AMD64"
    | Register  | Type          | Related       | Description                                       |
    |-----------|---------------|-----------------|---------------------------------------------------|
    | **General Purpose** |
    | RAX       | Integer        | EAX, AX, AH, AL | Accumulator register                              |
    | RBX       | Integer        | EBX, BX, BH, BL | Base register                                     |
    | RCX       | Integer        | ECX, CX, CH, CL | Counter register                                  |
    | RDX       | Integer        | EDX, DX, DH, DL | Data register                                     |
    | RSI       | Integer        | ESI, SI         | Source index for string operations                |
    | RDI       | Integer        | EDI, DI         | Destination index for string operations           |
    | RBP       | Integer        | EBP, BP         | Base pointer (frame pointer)                      |
    | RSP       | Integer        | ESP, SP         | Stack pointer                                     |
    | R8        | Integer        | R8D, R8W, R8B   | General-purpose register                          |
    | R9        | Integer        | R9D, R9W, R9B   | General-purpose register                          |
    | R10       | Integer        | R10D, R10W, R10B| General-purpose register                          |
    | R11       | Integer        | R11D, R11W, R11B| General-purpose register                          |
    | R12       | Integer        | R12D, R12W, R12B| General-purpose register                          |
    | R13       | Integer        | R13D, R13W, R13B| General-purpose register                          |
    | R14       | Integer        | R14D, R14W, R14B| General-purpose register                          |
    | R15       | Integer        | R15D, R15W, R15B| General-purpose register                          |
    | RIP       | Integer        | EIP             | Instruction pointer                               |
    | **Floating Point Registers** |
    | XMM0      | Floating Point |                 | Lower 128 bits of YMM0/ZMM0                       |
    | XMM1      | Floating Point |                 | Lower 128 bits of YMM1/ZMM1                       |
    | XMM2      | Floating Point |                 | Lower 128 bits of YMM2/ZMM2                       |
    | XMM3      | Floating Point |                 | Lower 128 bits of YMM3/ZMM3                       |
    | XMM4      | Floating Point |                 | Lower 128 bits of YMM4/ZMM4                       |
    | XMM5      | Floating Point |                 | Lower 128 bits of YMM5/ZMM5                       |
    | XMM6      | Floating Point |                 | Lower 128 bits of YMM6/ZMM6                       |
    | XMM7      | Floating Point |                 | Lower 128 bits of YMM7/ZMM7                       |
    | XMM8      | Floating Point |                 | Lower 128 bits of YMM8/ZMM8                       |
    | XMM9      | Floating Point |                 | Lower 128 bits of YMM9/ZMM9                       |
    | XMM10     | Floating Point |                 | Lower 128 bits of YMM10/ZMM10                     |
    | XMM11     | Floating Point |                 | Lower 128 bits of YMM11/ZMM11                     |
    | XMM12     | Floating Point |                 | Lower 128 bits of YMM12/ZMM12                     |
    | XMM13     | Floating Point |                 | Lower 128 bits of YMM13/ZMM13                     |
    | XMM14     | Floating Point |                 | Lower 128 bits of YMM14/ZMM14                     |
    | XMM15     | Floating Point |                 | Lower 128 bits of YMM15/ZMM15                     |
    | YMM0      | Floating Point |                 | 256-bit AVX extension of XMM0                     |
    | YMM1      | Floating Point |                 | 256-bit AVX extension of XMM1                     |
    | YMM2      | Floating Point |                 | 256-bit AVX extension of XMM2                     |
    | YMM3      | Floating Point |                 | 256-bit AVX extension of XMM3                     |
    | YMM4      | Floating Point |                 | 256-bit AVX extension of XMM4                     |
    | YMM5      | Floating Point |                 | 256-bit AVX extension of XMM5                     |
    | YMM6      | Floating Point |                 | 256-bit AVX extension of XMM6                     |
    | YMM7      | Floating Point |                 | 256-bit AVX extension of XMM7                     |
    | YMM8      | Floating Point |                 | 256-bit AVX extension of XMM8                     |
    | YMM9      | Floating Point |                 | 256-bit AVX extension of XMM9                     |
    | YMM10     | Floating Point |                 | 256-bit AVX extension of XMM10                    |
    | YMM11     | Floating Point |                 | 256-bit AVX extension of XMM11                    |
    | YMM12     | Floating Point |                 | 256-bit AVX extension of XMM12                    |
    | YMM13     | Floating Point |                 | 256-bit AVX extension of XMM13                    |
    | YMM14     | Floating Point |                 | 256-bit AVX extension of XMM14                    |
    | YMM15     | Floating Point |                 | 256-bit AVX extension of XMM15                    |
    | ZMM0      | Floating Point |                 | 512-bit AVX-512 extension of XMM0                 |
    | ZMM1      | Floating Point |                 | 512-bit AVX-512 extension of XMM1                 |
    | ZMM2      | Floating Point |                 | 512-bit AVX-512 extension of XMM2                 |
    | ZMM3      | Floating Point |                 | 512-bit AVX-512 extension of XMM3                 |
    | ZMM4      | Floating Point |                 | 512-bit AVX-512 extension of XMM4                 |
    | ZMM5      | Floating Point |                 | 512-bit AVX-512 extension of XMM5                 |
    | ZMM6      | Floating Point |                 | 512-bit AVX-512 extension of XMM6                 |
    | ZMM7      | Floating Point |                 | 512-bit AVX-512 extension of XMM7                 |
    | ZMM8      | Floating Point |                 | 512-bit AVX-512 extension of XMM8                 |
    | ZMM9      | Floating Point |                 | 512-bit AVX-512 extension of XMM9                 |
    | ZMM10     | Floating Point |                 | 512-bit AVX-512 extension of XMM10                |
    | ZMM11     | Floating Point |                 | 512-bit AVX-512 extension of XMM11                |
    | ZMM12     | Floating Point |                 | 512-bit AVX-512 extension of XMM12                |
    | ZMM13     | Floating Point |                 | 512-bit AVX-512 extension of XMM13                |
    | ZMM14     | Floating Point |                 | 512-bit AVX-512 extension of XMM14                |
    | ZMM15     | Floating Point |                 | 512-bit AVX-512 extension of XMM15                |
    | **Floating Point (Legacy x87)** |
    | ST(0)-ST(7)| Floating Point |                 | x87 FPU data registers                            |
    | MM0-MM7    | Floating Point |                 | MMX registers                                     |
=== "AArch64"
    | Register  | Type            | Alias(es)        | Description                                      |
    |-----------|-----------------|------------------|--------------------------------------------------|
    | **General Purpose** |
    | X0        | Integer          | W0               | Function result or argument                      |
    | X1        | Integer          | W1               | Function result or argument                      |
    | X2        | Integer          | W2               | Function result or argument                      |
    | X3        | Integer          | W3               | Function result or argument                      |
    | X4        | Integer          | W4               | Function result or argument                      |
    | X5        | Integer          | W5               | Function result or argument                      |
    | X6        | Integer          | W6               | Function result or argument                      |
    | X7        | Integer          | W7               | Function result or argument                      |
    | X8        | Integer          | W8               | Indirect result location (also called "IP0")     |
    | X9        | Integer          | W9               | Temporary register                               |
    | X10       | Integer          | W10              | Temporary register                               |
    | X11       | Integer          | W11              | Temporary register                               |
    | X12       | Integer          | W12              | Temporary register                               |
    | X13       | Integer          | W13              | Temporary register                               |
    | X14       | Integer          | W14              | Temporary register                               |
    | X15       | Integer          | W15              | Temporary register (also called "IP1")           |
    | X16       | Integer          | W16              | Platform Register (often used as scratch)        |
    | X17       | Integer          | W17              | Platform Register (often used as scratch)        |
    | X18       | Integer          | W18              | Platform Register                                |
    | X19       | Integer          | W19              | Callee-saved register                            |
    | X20       | Integer          | W20              | Callee-saved register                            |
    | X21       | Integer          | W21              | Callee-saved register                            |
    | X22       | Integer          | W22              | Callee-saved register                            |
    | X23       | Integer          | W23              | Callee-saved register                            |
    | X24       | Integer          | W24              | Callee-saved register                            |
    | X25       | Integer          | W25              | Callee-saved register                            |
    | X26       | Integer          | W26              | Callee-saved register                            |
    | X27       | Integer          | W27              | Callee-saved register                            |
    | X28       | Integer          | W28              | Callee-saved register                            |
    | X29       | Integer          | W29, FP          | Frame pointer                                    |
    | X30       | Integer          | W30, LR          | Link register (return address)                   |
    | XZR       | Integer          | WZR, ZR          | Zero register (always reads as zero)             |
    | SP        | Integer          |                  | Stack pointer                                    |
    | PC        | Integer          |                  | Program counter                                  |
    | **Floating Point Registers (SIMD/FP)** |
    | V0        | Floating Point   |                  | Vector or scalar register                        |
    | V1        | Floating Point   |                  | Vector or scalar register                        |
    | V2        | Floating Point   |                  | Vector or scalar register                        |
    | V3        | Floating Point   |                  | Vector or scalar register                        |
    | V4        | Floating Point   |                  | Vector or scalar register                        |
    | V5        | Floating Point   |                  | Vector or scalar register                        |
    | V6        | Floating Point   |                  | Vector or scalar register                        |
    | V7        | Floating Point   |                  | Vector or scalar register                        |
    | V8        | Floating Point   |                  | Vector or scalar register                        |
    | V9        | Floating Point   |                  | Vector or scalar register                        |
    | V10       | Floating Point   |                  | Vector or scalar register                        |
    | V11       | Floating Point   |                  | Vector or scalar register                        |
    | V12       | Floating Point   |                  | Vector or scalar register                        |
    | V13       | Floating Point   |                  | Vector or scalar register                        |
    | V14       | Floating Point   |                  | Vector or scalar register                        |
    | V15       | Floating Point   |                  | Vector or scalar register                        |
    | V16       | Floating Point   |                  | Vector or scalar register                        |
    | V17       | Floating Point   |                  | Vector or scalar register                        |
    | V18       | Floating Point   |                  | Vector or scalar register                        |
    | V19       | Floating Point   |                  | Vector or scalar register                        |
    | V20       | Floating Point   |                  | Vector or scalar register                        |
    | V21       | Floating Point   |                  | Vector or scalar register                        |
    | V22       | Floating Point   |                  | Vector or scalar register                        |
    | V23       | Floating Point   |                  | Vector or scalar register                        |
    | V24       | Floating Point   |                  | Vector or scalar register                        |
    | V25       | Floating Point   |                  | Vector or scalar register                        |
    | V26       | Floating Point   |                  | Vector or scalar register                        |
    | V27       | Floating Point   |                  | Vector or scalar register                        |
    | V28       | Floating Point   |                  | Vector or scalar register                        |
    | V29       | Floating Point   |                  | Vector or scalar register                        |
    | V30       | Floating Point   |                  | Vector or scalar register                        |
    | V31       | Floating Point   |                  | Vector or scalar register                        |
    | Q0        | Floating Point   |                  | Vector or scalar register                        |
    | Q1        | Floating Point   |                  | Vector or scalar register                        |
    | Q2        | Floating Point   |                  | Vector or scalar register                        |
    | Q3        | Floating Point   |                  | Vector or scalar register                        |
    | Q4        | Floating Point   |                  | Vector or scalar register                        |
    | Q5        | Floating Point   |                  | Vector or scalar register                        |
    | Q6        | Floating Point   |                  | Vector or scalar register                        |
    | Q7        | Floating Point   |                  | Vector or scalar register                        |
    | Q8        | Floating Point   |                  | Vector or scalar register                        |
    | Q9        | Floating Point   |                  | Vector or scalar register                        |
    | Q10       | Floating Point   |                  | Vector or scalar register                        |
    | Q11       | Floating Point   |                  | Vector or scalar register                        |
    | Q12       | Floating Point   |                  | Vector or scalar register                        |
    | Q13       | Floating Point   |                  | Vector or scalar register                        |
    | Q14       | Floating Point   |                  | Vector or scalar register                        |
    | Q15       | Floating Point   |                  | Vector or scalar register                        |
    | Q16       | Floating Point   |                  | Vector or scalar register                        |
    | Q17       | Floating Point   |                  | Vector or scalar register                        |
    | Q18       | Floating Point   |                  | Vector or scalar register                        |
    | Q19       | Floating Point   |                  | Vector or scalar register                        |
    | Q20       | Floating Point   |                  | Vector or scalar register                        |
    | Q21       | Floating Point   |                  | Vector or scalar register                        |
    | Q22       | Floating Point   |                  | Vector or scalar register                        |
    | Q23       | Floating Point   |                  | Vector or scalar register                        |
    | Q24       | Floating Point   |                  | Vector or scalar register                        |
    | Q25       | Floating Point   |                  | Vector or scalar register                        |
    | Q26       | Floating Point   |                  | Vector or scalar register                        |
    | Q27       | Floating Point   |                  | Vector or scalar register                        |
    | Q28       | Floating Point   |                  | Vector or scalar register                        |
    | Q29       | Floating Point   |                  | Vector or scalar register                        |
    | Q30       | Floating Point   |                  | Vector or scalar register                        |
    | Q31       | Floating Point   |                  | Vector or scalar register                        |
    | D0        | Floating Point   |                  | Vector or scalar register                        |
    | D1        | Floating Point   |                  | Vector or scalar register                        |
    | D2        | Floating Point   |                  | Vector or scalar register                        |
    | D3        | Floating Point   |                  | Vector or scalar register                        |
    | D4        | Floating Point   |                  | Vector or scalar register                        |
    | D5        | Floating Point   |                  | Vector or scalar register                        |
    | D6        | Floating Point   |                  | Vector or scalar register                        |
    | D7        | Floating Point   |                  | Vector or scalar register                        |
    | D8        | Floating Point   |                  | Vector or scalar register                        |
    | D9        | Floating Point   |                  | Vector or scalar register                        |
    | D10       | Floating Point   |                  | Vector or scalar register                        |
    | D11       | Floating Point   |                  | Vector or scalar register                        |
    | D12       | Floating Point   |                  | Vector or scalar register                        |
    | D13       | Floating Point   |                  | Vector or scalar register                        |
    | D14       | Floating Point   |                  | Vector or scalar register                        |
    | D15       | Floating Point   |                  | Vector or scalar register                        |
    | D16       | Floating Point   |                  | Vector or scalar register                        |
    | D17       | Floating Point   |                  | Vector or scalar register                        |
    | D18       | Floating Point   |                  | Vector or scalar register                        |
    | D19       | Floating Point   |                  | Vector or scalar register                        |
    | D20       | Floating Point   |                  | Vector or scalar register                        |
    | D21       | Floating Point   |                  | Vector or scalar register                        |
    | D22       | Floating Point   |                  | Vector or scalar register                        |
    | D23       | Floating Point   |                  | Vector or scalar register                        |
    | D24       | Floating Point   |                  | Vector or scalar register                        |
    | D25       | Floating Point   |                  | Vector or scalar register                        |
    | D26       | Floating Point   |                  | Vector or scalar register                        |
    | D27       | Floating Point   |                  | Vector or scalar register                        |
    | D28       | Floating Point   |                  | Vector or scalar register                        |
    | D29       | Floating Point   |                  | Vector or scalar register                        |
    | D30       | Floating Point   |                  | Vector or scalar register                        |
    | D31       | Floating Point   |                  | Vector or scalar register                        |
    | S0        | Floating Point   |                  | Vector or scalar register                        |
    | S1        | Floating Point   |                  | Vector or scalar register                        |
    | S2        | Floating Point   |                  | Vector or scalar register                        |
    | S3        | Floating Point   |                  | Vector or scalar register                        |
    | S4        | Floating Point   |                  | Vector or scalar register                        |
    | S5        | Floating Point   |                  | Vector or scalar register                        |
    | S6        | Floating Point   |                  | Vector or scalar register                        |
    | S7        | Floating Point   |                  | Vector or scalar register                        |
    | S8        | Floating Point   |                  | Vector or scalar register                        |
    | S9        | Floating Point   |                  | Vector or scalar register                        |
    | S10       | Floating Point   |                  | Vector or scalar register                        |
    | S11       | Floating Point   |                  | Vector or scalar register                        |
    | S12       | Floating Point   |                  | Vector or scalar register                        |
    | S13       | Floating Point   |                  | Vector or scalar register                        |
    | S14       | Floating Point   |                  | Vector or scalar register                        |
    | S15       | Floating Point   |                  | Vector or scalar register                        |
    | S16       | Floating Point   |                  | Vector or scalar register                        |
    | S17       | Floating Point   |                  | Vector or scalar register                        |
    | S18       | Floating Point   |                  | Vector or scalar register                        |
    | S19       | Floating Point   |                  | Vector or scalar register                        |
    | S20       | Floating Point   |                  | Vector or scalar register                        |
    | S21       | Floating Point   |                  | Vector or scalar register                        |
    | S22       | Floating Point   |                  | Vector or scalar register                        |
    | S23       | Floating Point   |                  | Vector or scalar register                        |
    | S24       | Floating Point   |                  | Vector or scalar register                        |
    | S25       | Floating Point   |                  | Vector or scalar register                        |
    | S26       | Floating Point   |                  | Vector or scalar register                        |
    | S27       | Floating Point   |                  | Vector or scalar register                        |
    | S28       | Floating Point   |                  | Vector or scalar register                        |
    | S29       | Floating Point   |                  | Vector or scalar register                        |
    | S30       | Floating Point   |                  | Vector or scalar register                        |
    | S31       | Floating Point   |                  | Vector or scalar register                        |
    | H0        | Floating Point   |                  | Vector or scalar register                        |
    | H1        | Floating Point   |                  | Vector or scalar register                        |
    | H2        | Floating Point   |                  | Vector or scalar register                        |
    | H3        | Floating Point   |                  | Vector or scalar register                        |
    | H4        | Floating Point   |                  | Vector or scalar register                        |
    | H5        | Floating Point   |                  | Vector or scalar register                        |
    | H6        | Floating Point   |                  | Vector or scalar register                        |
    | H7        | Floating Point   |                  | Vector or scalar register                        |
    | H8        | Floating Point   |                  | Vector or scalar register                        |
    | H9        | Floating Point   |                  | Vector or scalar register                        |
    | H10       | Floating Point   |                  | Vector or scalar register                        |
    | H11       | Floating Point   |                  | Vector or scalar register                        |
    | H12       | Floating Point   |                  | Vector or scalar register                        |
    | H13       | Floating Point   |                  | Vector or scalar register                        |
    | H14       | Floating Point   |                  | Vector or scalar register                        |
    | H15       | Floating Point   |                  | Vector or scalar register                        |
    | H16       | Floating Point   |                  | Vector or scalar register                        |
    | H17       | Floating Point   |                  | Vector or scalar register                        |
    | H18       | Floating Point   |                  | Vector or scalar register                        |
    | H19       | Floating Point   |                  | Vector or scalar register                        |
    | H20       | Floating Point   |                  | Vector or scalar register                        |
    | H21       | Floating Point   |                  | Vector or scalar register                        |
    | H22       | Floating Point   |                  | Vector or scalar register                        |
    | H23       | Floating Point   |                  | Vector or scalar register                        |
    | H24       | Floating Point   |                  | Vector or scalar register                        |
    | H25       | Floating Point   |                  | Vector or scalar register                        |
    | H26       | Floating Point   |                  | Vector or scalar register                        |
    | H27       | Floating Point   |                  | Vector or scalar register                        |
    | H28       | Floating Point   |                  | Vector or scalar register                        |
    | H29       | Floating Point   |                  | Vector or scalar register                        |
    | H30       | Floating Point   |                  | Vector or scalar register                        |
    | H31       | Floating Point   |                  | Vector or scalar register                        |
    | B0        | Floating Point   |                  | Vector or scalar register                        |
    | B1        | Floating Point   |                  | Vector or scalar register                        |
    | B2        | Floating Point   |                  | Vector or scalar register                        |
    | B3        | Floating Point   |                  | Vector or scalar register                        |
    | B4        | Floating Point   |                  | Vector or scalar register                        |
    | B5        | Floating Point   |                  | Vector or scalar register                        |
    | B6        | Floating Point   |                  | Vector or scalar register                        |
    | B7        | Floating Point   |                  | Vector or scalar register                        |
    | B8        | Floating Point   |                  | Vector or scalar register                        |
    | B9        | Floating Point   |                  | Vector or scalar register                        |
    | B10       | Floating Point   |                  | Vector or scalar register                        |
    | B11       | Floating Point   |                  | Vector or scalar register                        |
    | B12       | Floating Point   |                  | Vector or scalar register                        |
    | B13       | Floating Point   |                  | Vector or scalar register                        |
    | B14       | Floating Point   |                  | Vector or scalar register                        |
    | B15       | Floating Point   |                  | Vector or scalar register                        |
    | B16       | Floating Point   |                  | Vector or scalar register                        |
    | B17       | Floating Point   |                  | Vector or scalar register                        |
    | B18       | Floating Point   |                  | Vector or scalar register                        |
    | B19       | Floating Point   |                  | Vector or scalar register                        |
    | B20       | Floating Point   |                  | Vector or scalar register                        |
    | B21       | Floating Point   |                  | Vector or scalar register                        |
    | B22       | Floating Point   |                  | Vector or scalar register                        |
    | B23       | Floating Point   |                  | Vector or scalar register                        |
    | B24       | Floating Point   |                  | Vector or scalar register                        |
    | B25       | Floating Point   |                  | Vector or scalar register                        |
    | B26       | Floating Point   |                  | Vector or scalar register                        |
    | B27       | Floating Point   |                  | Vector or scalar register                        |
    | B28       | Floating Point   |                  | Vector or scalar register                        |
    | B29       | Floating Point   |                  | Vector or scalar register                        |
    | B30       | Floating Point   |                  | Vector or scalar register                        |
    | B31       | Floating Point   |                  | Vector or scalar register                        |


!!! INFO "Hardware Support"
    **libdebug** only exposes registers which are available on your CPU model. For AMD64, the list of available AVX registers is determined by checking the CPU capabilities. If you believe your CPU supports AVX registers but they are not available, we encourage your to open an [:octicons-issue-opened-24: Issue](https://github.com/libdebug/libdebug/issues) with your hardware details.

## :octicons-search-24: Searching inside Registers
The `regs` field of the [Debugger](../../from_pydoc/generated/debugger/debugger/) object or the [Thread Context](../../from_pydoc/generated/state/thread_context) can also used to search for specific values inside the registers. 


!!! ABSTRACT "Function Signature"
    ```python
    d.regs.find(value: float) -> list[str]:
    ```

The search routine will look for the given value in integer registers when the `value` is an int and in floating point registers when the value is a `float`.

!!! ABSTRACT "Searching for a Value"
    ```python
    d.regs.rax = 0x1337
    
    # Search for the value 0x1337 in the registers
    results = d.regs.find(0x1337)
    print(f"Found in: {results}")
    ```