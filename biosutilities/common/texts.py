#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""


def to_string(in_object: str | list | tuple, sep_char: str = '') -> str:
    """ Get string from given input object """

    if isinstance(in_object, (list, tuple)):
        out_string: str = sep_char.join(map(str, in_object))
    else:
        out_string = str(in_object)

    return out_string


def to_ordinal(in_number: int) -> str:
    """
    Get ordinal (textual) representation of input numerical value

    https://leancrew.com/all-this/2020/06/ordinals-in-python/ by Dr. Drang
    """

    ordinals: list[str] = ['th', 'st', 'nd', 'rd'] + ['th'] * 10

    numerical: int = in_number % 100

    if numerical > 13:
        return f'{in_number}{ordinals[numerical % 10]}'

    return f'{in_number}{ordinals[numerical]}'


def file_to_bytes(in_object: str | bytes | bytearray) -> bytes:
    """ Get bytes from given buffer or file path """

    if not isinstance(in_object, (bytes, bytearray)):
        with open(file=to_string(in_object=in_object), mode='rb') as object_data:
            object_bytes: bytes = object_data.read()
    else:
        object_bytes = in_object

    return object_bytes


def bytes_to_hex(in_buffer: bytes, order: str, data_len: int, slice_len: int | None = None) -> str:
    """ Converts bytes to hex string, controlling endianess, data size and string slicing """

    # noinspection PyTypeChecker
    return f'{int.from_bytes(bytes=in_buffer, byteorder=order):0{data_len * 2}X}'[:slice_len]  # type: ignore


def remove_quotes(in_text: str) -> str:
    """ Remove leading/trailing quotes from path """

    out_text: str = to_string(in_object=in_text).strip()

    if len(out_text) >= 2:
        if (out_text[0] == '"' and out_text[-1] == '"') or (out_text[0] == "'" and out_text[-1] == "'"):
            out_text = out_text[1:-1]

    return out_text


def to_boxed(in_text: str) -> str:
    """ Box string into two horizontal lines of same size """

    box_line: str = '-' * len(to_string(in_object=in_text))

    return f'{box_line}\n{in_text}\n{box_line}'
