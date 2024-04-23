#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import ctypes

Char: type[ctypes.c_char] | int = ctypes.c_char
UInt8: type[ctypes.c_ubyte] | int = ctypes.c_ubyte
UInt16: type[ctypes.c_ushort] | int = ctypes.c_ushort
UInt32: type[ctypes.c_uint] | int = ctypes.c_uint
UInt64: type[ctypes.c_uint64] | int = ctypes.c_uint64


def get_struct(buffer, start_offset, class_name, param_list=None):
    """
    https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
    """

    parameters = [] if param_list is None else param_list

    structure = class_name(*parameters)  # Unpack parameter list

    struct_len = ctypes.sizeof(structure)

    struct_data = buffer[start_offset:start_offset + struct_len]

    fit_len = min(len(struct_data), struct_len)

    ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)

    return structure
