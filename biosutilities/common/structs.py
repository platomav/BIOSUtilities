#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2025 Plato Mavropoulos
"""

import ctypes

from typing import Any, Final

CHAR: Final[Any] = ctypes.c_char
UINT8: Final[Any] = ctypes.c_ubyte
UINT16: Final[Any] = ctypes.c_ushort
UINT32: Final[Any] = ctypes.c_uint
UINT64: Final[Any] = ctypes.c_uint64


def ctypes_struct(buffer: bytes | bytearray, start_offset: int, class_object: Any,
                  param_list: list | None = None) -> Any:
    """
    https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
    """

    if not param_list:
        param_list = []

    structure: Any = class_object(*param_list)

    struct_len: int = ctypes.sizeof(structure)

    struct_data: bytes | bytearray = buffer[start_offset:start_offset + struct_len]

    least_len: int = min(len(struct_data), struct_len)

    ctypes.memmove(ctypes.addressof(structure), struct_data, least_len)

    return structure
