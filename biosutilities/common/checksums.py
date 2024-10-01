#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""


# Get Checksum 16-bit
def checksum_16(data: bytes | bytearray, value: int = 0, order: str = 'little') -> int:
    """ Calculate Checksum-16 of data, controlling IV and Endianess """

    for idx in range(0, len(data), 2):
        # noinspection PyTypeChecker
        value += int.from_bytes(bytes=data[idx:idx + 2], byteorder=order)  # type: ignore

    value &= 0xFFFF

    return value


# Get Checksum 8-bit XOR
def checksum_8_xor(data: bytes | bytearray, value: int = 0) -> int:
    """ Calculate Checksum-8 XOR of data, controlling IV """

    for byte in data:
        value ^= byte

    value ^= 0x0

    return value
