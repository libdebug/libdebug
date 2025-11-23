#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

DETECTION_PATTERNS = [
    # AUT (AUT R12, LR, SP)
    {
        "value": 0b11110011101011111000000000101101,
        "mask": 0b11111111111111111111111111111111,
    },
    # AUTG
    {
        "value": 0b11111011010100000000001111000000000,
        "mask": 0b11111111111100000000001111111100000,
    },
    # BXAUT
    {
        "value": 0b11111011010100000000001111000100000,
        "mask": 0b11111111111100000000001111111100000,
    },
    # PAC (PAC R12, LR, SP)
    {
        "value": 0b11110011101011111000000000011101,
        "mask": 0b11111111111111111111111111111111,
    },
    # PACG
    {
        "value": 0b11111011011000000111100000000000000,
        "mask": 0b11111111111100000111100000111100000,
    },
    # PACBTI (PACBTI R12, LR, SP)
    {
        "value": 0b11110011101011111000000000001101,
        "mask": 0b11111111111111111111111111111111,
    },
    # AUTDA, AUTDZA
    {
        "value": 0b11011010110000010001100000000000,
        "mask": 0b11111111111111111101110000000000,
    },
    # AUTDB, AUTDZB
    {
        "value": 0b11011010110000010001110000000000,
        "mask": 0b11111111111111111101110000000000,
    },
    # AUTIA, AUTIA1716, AUTIASP, AUTIAZ, AUTIZA
    {
        "value": 0b11011010110000010001000000000000,
        "mask": 0b11111111111111111101110000000000,
    },
    {
        "value": 0b11010101000000110010000110011111,
        "mask": 0b11111111111111111111110111011111,
    },
    # AUTIA171615
    {
        "value": 0b11011010110000011011101111111110,
        "mask": 0b11111111111111111111111111111111,
    },
    # AUTIASPPC
    {
        "value": 0b11110011100000000000000000011111,
        "mask": 0b11111111111000000000000000011111,
    },
    # AUTIASPPCR
    {
        "value": 0b11011010110000011001000000011110,
        "mask": 0b11111111111111111111110000011111,
    },
    # AUTIB, AUTIB1716, AUTIBSP, AUTIBZ, AUTIZB
    {
        "value": 0b11011010110000010001010000000000,
        "mask": 0b11111111111111111101110000000000,
    },
    {
        "value": 0b11010101000000110010000111011111,
        "mask": 0b11111111111111111111110111011111,
    },
    # AUTIB171615
    {
        "value": 0b11011010110000011011111111111110,
        "mask": 0b11111111111111111111111111111111,
    },
    # AUTIBSPPC
    {
        "value": 0b11110011101000000000000000011111,
        "mask": 0b11111111111000000000000000011111,
    },
    # AUTIBSPPCR
    {
        "value": 0b11011010110000011001010000011110,
        "mask": 0b11111111111111111111110000011111,
    },
    # BLRAA, BLRAAZ, BLRAB, BLRABZ
    {
        "value": 0b11010110001111110000100000000000,
        "mask": 0b11111110111111111111100000000000,
    },
    # BRAA, BRAAZ, BRAB, BRABZ
    {
        "value": 0b11010110000111110000100000000000,
        "mask": 0b11111110111111111111100000000000,
    },
    # ERETAA, ERETAB
    {
        "value": 0b11010110100111110000101111111111,
        "mask": 0b11111111111111111111101111111111,
    },
    # LDRAA, LDRAB
    {
        "value": 0b11111000001000000000010000000000,
        "mask": 0b11111111001000000000010000000000,
    },
    # PACDA, PACDZA
    {
        "value": 0b11011010110000010000100000000000,
        "mask": 0b11111111111111111101110000000000,
    },
    # PACDB, PACDZB
    {
        "value": 0b11011010110000010000110000000000,
        "mask": 0b11111111111111111101110000000000,
    },
    # PACGA
    {
        "value": 0b10011010110000000011000000000000,
        "mask": 0b11111111111000001111110000000000,
    },
    # PACIA, PACIA1716, PACIASP, PACIAZ, PACIZA
    {
        "value": 0b11011010110000010000000000000000,
        "mask": 0b11111111111111111101110000000000,
    },
    {
        "value": 0b11010101000000110010000100011111,
        "mask": 0b11111111111111111111110111011111,
    },
    # PACIA171615
    {
        "value": 0b11011010110000011000101111111110,
        "mask": 0b11111111111111111111111111111111,
    },
    # PACIASPPC
    {
        "value": 0b11011010110000011010001111111110,
        "mask": 0b11111111111111111111111111111111,
    },
    # PACIB, PACIB1716, PACIBSP, PACIBZ, PACIZB
    {
        "value": 0b11011010110000010000010000000000,
        "mask": 0b11111111111111111101110000000000,
    },
    {
        "value": 0b11010101000000110010000101011111,
        "mask": 0b11111111111111111111110111011111,
    },
    # PACIB171615
    {
        "value": 0b11011010110000011000111111111110,
        "mask": 0b11111111111111111111111111111111,
    },
    # PACIBSPPC
    {
        "value": 0b11011010110000011010011111111110,
        "mask": 0b11111111111111111111111111111111,
    },
    # PACM
    {
        "value": 0b11010101000000110010010011111111,
        "mask": 0b11111111111111111111111111111111,
    },
    # PACNBIASPPC
    {
        "value": 0b11011010110000011000001111111110,
        "mask": 0b11111111111111111111111111111111,
    },
    # PACNBIBSPPC
    {
        "value": 0b11011010110000011000011111111110,
        "mask": 0b11111111111111111111111111111111,
    },
    # RETAA, RETAB
    {
        "value": 0b11010110010111110000101111111111,
        "mask": 0b11111111111111111111101111111111,
    },
    # RETAASPPC, RETABSPPC
    {
        "value": 0b01010101000000000000000000011111,
        "mask": 0b11111111110000000000000000011111,
    },
    # XPACD, XPACI, XPACLRI
    {
        "value": 0b11011010110000010100001111100000,
        "mask": 0b11111111111111111111101111100000,
    },
    {
        "value": 0b11010101000000110010000011111111,
        "mask": 0b11111111111111111111111111111111,
    },
]

def detect_pac_pattern_in_code(code: bytes) -> bool:
    """
    Detects if the given code contains any PAC-related instructions based on predefined detection patterns.

    Args:
        code (bytes): The binary code to analyze.

    Returns:
        bool: True if any PAC-related instruction is detected, False otherwise.
    """
    code_length = len(code)
    for i in range(0, code_length - 4 + 1, 4):
        instruction = int.from_bytes(code[i:i+4], byteorder="little")
        for pattern in DETECTION_PATTERNS:
            value = pattern["value"]
            mask = pattern["mask"]
            if (instruction & mask) == (value & mask):
                return True
    return False
