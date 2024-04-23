#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""


def padder(padd_count, tab=False):
    """ Generate padding (spaces or tabs) """

    return ('\t' if tab else ' ') * padd_count


def to_string(in_object, sep_char=''):
    """ Get String from given input object """

    if type(in_object).__name__ in ('list', 'tuple'):
        out_string = sep_char.join(map(str, in_object))
    else:
        out_string = str(in_object)

    return out_string


def file_to_bytes(in_object):
    """ Get Bytes from given buffer or file path """

    object_bytes = in_object

    if type(in_object).__name__ not in ('bytes', 'bytearray'):
        with open(to_string(in_object), 'rb') as object_data:
            object_bytes = object_data.read()

    return object_bytes


def bytes_to_hex(buffer: bytes, order: str, data_len: int, slice_len: int | None = None) -> str:
    """ Converts bytes to hex string, controlling endianess, data size and string slicing """

    # noinspection PyTypeChecker
    return f'{int.from_bytes(buffer, order):0{data_len * 2}X}'[:slice_len]


def is_encased(in_string, chars):
    """ Check if string starts and ends with given character(s) """

    return in_string.startswith(chars) and in_string.endswith(chars)
