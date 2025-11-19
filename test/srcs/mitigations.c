#include <stdio.h>
#include <stdint.h>
#include <string.h>

// ------------------ Build Instructions ------------------- //
//                          AMD64                            //
// --------------------------------------------------------- //
// v1
// ╭──────────── Mitigations ─────────────╮
// │ Runtime Mitigations                  │
// │ ├── 🧱 RELRO: Full                   │
// │ ├── 🛡 Stack Guard (canary): Enabled │
// │ ├── 👾 NX: Enabled                   │
// │ ├── 🧵 Stack: Non-executable         │
// │ ├── 🧩 PIE: Enabled                  │
// │ ├── Intel CET                        │
// │ │   ├── ↳  ☰ Shadow Stack: Enabled  │
// │ │   └── ↳  🧭 IBT: Enabled          │
// │ └── 🏰 FORTIFY_SOURCE: Enabled       │
// ╰──────────────────────────────────────╯
//
// gcc -O2 -fstack-protector -D_FORTIFY_SOURCE=2 -fPIE -Wl,-z,relro,-z,now -fcf-protection=full -o ../binaries/amd64/mitigationsv1 mitigations.c
//
// ---------
// v2
// ╭──────────── Mitigations ────────────╮
// │ Runtime Mitigations                 │
// │ ├── 🧱 RELRO: Partial               │
// │ ├── 🛡 Stack Guard (canary): Enabled│
// │ ├── 👾 NX: Enabled                  │
// │ ├── 🧵 Stack: Non-executable        │
// │ ├── 🧩 PIE: Enabled                 │
// │ ├── Intel CET                       │
// │ │   ├── ↳  ☰ Shadow Stack: Disabled │
// │ │   └── ↳  🧭 IBT: Disabled         │
// │ └── 🏰 FORTIFY_SOURCE: Disabled     │
// ╰─────────────────────────────────────╯
//
// gcc -O2 -fstack-protector -D_FORTIFY_SOURCE=1 -fPIE -Wl,-z,relro -fcf-protection=none -o ../binaries/amd64/mitigationsv2 mitigations.c
// ---------
// v3
// ╭──────────── Mitigations ──────────────╮
// │ Runtime Mitigations                   │
// │ ├── 🧱 RELRO: None                    │
// │ ├── 🛡 Stack Guard (canary): Disabled |
// │ ├── 👾 NX: Depends                    │
// │ ├── 🧵 Stack: Executable              │
// │ ├── 🧩 PIE: Disabled                  │
// │ ├── Intel CET                         │
// │ │   ├── ↳  ☰ Shadow Stack: Disabled  │
// │ │   └── ↳  🧭 IBT: Disabled          │
// │ └── 🏰 FORTIFY_SOURCE: Disabled       │
// ╰───────────────────────────────────────╯
//
// gcc -O0 -U_FORTIFY_SOURCE=0 -no-pie -z norelro -fno-stack-protector -Wl,-z,execstack -fcf-protection=none -o ../binaries/amd64/mitigationsv3 mitigations.c
// ---------
// v4
// ╭──────────── Mitigations ────────────╮
// │ Runtime Mitigations                 │
// │ ├── 🧱 RELRO: Full                  │
// │ ├── 🛡 Stack Guard (canary): Enabled │
// │ ├── 👾 NX: Enabled                  │
// │ ├── 🧵 Stack: Non-executable        │
// │ ├── 🧩 PIE: Enabled                 │
// │ ├── Intel CET                       │
// │ │   ├── ↳  ☰ Shadow Stack: Disabled │
// │ │   └── ↳  🧭 IBT: Disabled         │
// │ ├── 🏰 FORTIFY_SOURCE: Enabled      │
// │ └── 🧪 ASan: Enabled                │
// ╰─────────────────────────────────────╯
//
// gcc -O2 -m32 -fstack-protector -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -fPIE -fsanitize=address -o ../binaries/amd64/mitigationsv6 mitigations.c
// --------------------------------------------------------- //

// ------------------ Build Instructions ------------------- //
//                           i386                            //
// --------------------------------------------------------- //
// v1
// ╭──────────── Mitigations ────────────╮
// │ Runtime Mitigations                 │
// │ ├── 🧱 RELRO: Full                  │
// │ ├── 🛡 Stack Guard (canary): Enabled│
// │ ├── 👾 NX: Enabled                  │
// │ ├── 🧵 Stack: Non-executable        │
// │ ├── 🧩 PIE: Enabled                 │
// │ ├── Intel CET                       │
// │ │   ├── ↳  ☰ Shadow Stack: Disabled │
// │ │   └── ↳  🧭 IBT: Disabled          │
// │ └── 🏰 FORTIFY_SOURCE: Enabled      │
// ╰─────────────────────────────────────╯
//
// gcc -O2 -m32 -fstack-protector -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -fPIE -o ../binaries/i386/mitigationsv1 mitigations.c
//
// ---------
// v2
// ╭──────────── Mitigations ────────────╮
// │ Runtime Mitigations                 │
// │ ├── 🧱 RELRO: Partial               │
// │ ├── 🛡 Stack Guard (canary): Enabled│
// │ ├── 👾 NX: Enabled                  │
// │ ├── 🧵 Stack: Non-executable        │
// │ ├── 🧩 PIE: Enabled                 │
// │ ├── Intel CET                       │
// │ │   ├── ↳  ☰ Shadow Stack: Disabled │
// │ │   └── ↳  🧭 IBT: Disabled         │
// │ └── 🏰 FORTIFY_SOURCE: Disabled     │
// ╰─────────────────────────────────────╯
//
// gcc -O1 -m32 -fstack-protector -D_FORTIFY_SOURCE=1 -fPIE -Wl,-z,relro -o ../binaries/i386/mitigationsv2 mitigations.c
// ---------
// v3
// ╭──────────── Mitigations ──────────────╮
// │ Runtime Mitigations                   │
// │ ├── 🧱 RELRO: None                    │
// │ ├── 🛡 Stack Guard (canary): Disabled |
// │ ├── 👾 NX: Depends                    │
// │ ├── 🧵 Stack: Executable              │
// │ ├── 🧩 PIE: Disabled                  │
// │ ├── Intel CET                         │
// │ │   ├── ↳  ☰ Shadow Stack: Disabled  │
// │ │   └── ↳  🧭 IBT: Disabled          │
// │ └── 🏰 FORTIFY_SOURCE: Disabled       │
// ╰───────────────────────────────────────╯
// gcc -O0 -m32 -U_FORTIFY_SOURCE -no-pie -z norelro -fno-stack-protector -Wl,-z,execstack -o ../binaries/i386/mitigationsv3 mitigations.c
// --------------------------------------------------------- //

// ------------------ Build Instructions ------------------- //
//                          AArch64                          //
// --------------------------------------------------------- //
// v1
// ╭──────────── Mitigations ──────────────╮
// │ Runtime Mitigations                   │
// │ ├── 🧱 RELRO: Full                    │
// │ ├── 🛡 Stack Guard (canary): Enabled  │
// │ ├── 👾 NX: Enabled                    │
// │ ├── 🧵 Stack: Non-executable          │
// │ ├── 🧩 PIE: Enabled                   │
// │ ├── ARM Architectural Hardening       │
// │ │   ├── ↳  ☰ GCS: Disabled           │
// │ │   ├── ↳  🧭 BTI: Disabled          │
// │ │   └── ↳  🔐 PAC: Disabled          │
// │ └── 🏰 FORTIFY_SOURCE: Enabled        │
// ╰───────────────────────────────────────╯
// aarch64-linux-gnu-gcc -O2 -fstack-protector -D_FORTIFY_SOURCE=2 -fPIE -Wl,-z,relro,-z,now -o ../binaries/aarch64/mitigationsv1 mitigations.c
// ---------
// v2
// ╭──────────── Mitigations ──────────────╮
// │ Runtime Mitigations                   │
// │ ├── 🧱 RELRO: Partial                 │
// │ ├── 🛡 Stack Guard (canary): Enabled  │
// │ ├── 👾 NX: Enabled                    │
// │ ├── 🧵 Stack: Non-executable          │
// │ ├── 🧩 PIE: Enabled                   │
// │ ├── ARM Architectural Hardening       │
// │ │   ├── ↳  ☰ GCS: Enabled            │
// │ │   ├── ↳  🧭 BTI: Disabled          │
// │ │   └── ↳  🔐 PAC: Enabled           │
// │ └── 🏰 FORTIFY_SOURCE: Enabled        │
// ╰───────────────────────────────────────╯
// glibc-2.42-mitigations-gcs.so
// GCS support is recent and still shaky. I was able to compile a GLIBC and loader for it, but cannot seem to
// link properly with it yet. While the PAC feature is not listed in the note, PAC instructions have been emitted.
// So the library is also PAC enabled.
// ---------
// v3
// ╭──────────── Mitigations ──────────────╮
// │ Runtime Mitigations                   │
// │ ├── 🧱 RELRO: Full                    │
// │ ├── 🛡 Stack Guard (canary): Enabled  │
// │ ├── 👾 NX: Enabled                    │
// │ ├── 🧵 Stack: Non-executable          │
// │ ├── 🧩 PIE: Enabled                   │
// │ ├── ARM Architectural Hardening       │
// │ │   ├── ↳  ☰ GCS: Disabled           │
// │ │   ├── ↳  🧭 BTI: Enabled            │
// │ │   └── ↳  🔐 PAC: Enabled            │
// │ └── 🏰 FORTIFY_SOURCE: Disabled       │
// ╰───────────────────────────────────────╯
// Natively compiled on an ARM VM
// gcc -O2 -fstack-protector -fPIE -pie -Wl,-z,relro -march=armv8.5-a -mbranch-protection=standard \
-B/opt/glibc-pacbti/lib \
-L/opt/glibc-pacbti/lib -Wl,--rpath=/opt/glibc-pacbti/lib \
-Wl,--dynamic-linker=/opt/glibc-pacbti/lib/ld-linux-aarch64.so.1 \
-o mitigationsv3 mitigations.c
// --------- //
// v4
// ╭──────────── Mitigations ──────────────╮
// │ Runtime Mitigations                   │
// │ ├── 🧱 RELRO: None                    │
// │ ├── 🛡 Stack Guard (canary): Disabled │
// │ ├── 👾 NX: Depends                    │
// │ ├── 🧵 Stack: Executable              │
// │ ├── 🧩 PIE: Disabled                  │
// │ ├── ARM Architectural Hardening       │
// │ │   ├── ↳  ☰ GCS: Disabled           │
// │ │   ├── ↳  🧭 BTI: Disabled          │
// │ │   └── ↳  🔐 PAC: Disabled          │
// │ └── 🏰 FORTIFY_SOURCE: Disabled       │
// ╰───────────────────────────────────────╯
// aarch64-linux-gnu-gcc -O0 -no-pie -z norelro \
 -fno-stack-protector -Wl,-z,execstack \
  -o ../binaries/aarch64/mitigationsv4 mitigations.c
// --------------------------------------------------------- //

int called_function(int x) 
{
    char buffer[12];
    char buf2[16];
    snprintf(buffer, sizeof(buffer), "Value: %d", x);

    return 42;
}

int main(int argc, char** argv, char** envp)
{
    int result = called_function(100);
    int new_result;

    memcpy(&new_result, &result, sizeof(result));
    
    printf("Result: %d\n", result);
    return 0;
}
