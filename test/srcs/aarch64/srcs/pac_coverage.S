/*
 * PAC instruction coverage test — one representative per detection pattern.
 *
 * Compile with:
 *   aarch64-linux-gnu-as -march=armv8.3-a -o pac_coverage.o pac_coverage.S
 *   aarch64-linux-gnu-ld -o pac_coverage pac_coverage.o
 */

.text
.global _start

_start:
    /* --- AUTDA, AUTDZA (pattern 0) --- */
    autda   x0, x1
    autdza  x2

    /* --- AUTDB, AUTDZB (pattern 1) --- */
    autdb   x0, x1
    autdzb  x2

    /* --- AUTIA, AUTIZA  (pattern 2: register form) --- */
    autia   x0, x1
    autiza  x2

    /* --- AUTIA1716, AUTIASP, AUTIAZ (pattern 3: hint form) --- */
    hint    #12          /* autia1716 */
    autiasp
    autiaz

    /* --- AUTIB, AUTIZB  (pattern 7: register form) --- */
    autib   x0, x1
    autizb  x2

    /* --- AUTIB1716, AUTIBSP, AUTIBZ (pattern 8: hint form) --- */
    hint    #14          /* autib1716 */
    autibsp
    autibz

    /* --- BLRAA, BLRAAZ, BLRAB, BLRABZ (pattern 12) --- */
    blraa   x0, x1
    blraaz  x0
    blrab   x0, x1
    blrabz  x0

    /* --- BRAA, BRAAZ, BRAB, BRABZ (pattern 13) --- */
    braa    x0, x1
    braaz   x0
    brab    x0, x1
    brabz   x0

    /* --- ERETAA, ERETAB (pattern 14) --- */
    eretaa
    eretab

    /* --- LDRAA, LDRAB (pattern 15) --- */
    ldraa   x0, [x1]
    ldrab   x0, [x1]

    /* --- PACDA, PACDZA (pattern 16) --- */
    pacda   x0, x1
    pacdza  x2

    /* --- PACDB, PACDZB (pattern 17) --- */
    pacdb   x0, x1
    pacdzb  x2

    /* --- PACGA (pattern 18) --- */
    pacga   x0, x1, x2

    /* --- PACIA, PACIZA (pattern 19: register form) --- */
    pacia   x0, x1
    paciza  x2

    /* --- PACIA1716, PACIASP, PACIAZ (pattern 20: hint form) --- */
    hint    #8           /* pacia1716 */
    paciasp
    paciaz

    /* --- PACIB, PACIZB (pattern 23: register form) --- */
    pacib   x0, x1
    pacizb  x2

    /* --- PACIB1716, PACIBSP, PACIBZ (pattern 24: hint form) --- */
    hint    #10          /* pacib1716 */
    pacibsp
    pacibz

    /* --- RETAA, RETAB (pattern 30) --- */
    retaa
    retab

    /* --- XPACD, XPACI (pattern 32: register form) --- */
    xpacd   x0
    xpaci   x1

    /* --- XPACLRI (pattern 33: hint form) --- */
    xpaclri

    /* Exit */
    mov     x0, #0
    mov     x8, #93
    svc     #0
