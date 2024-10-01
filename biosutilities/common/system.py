#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import sys
import platform

from biosutilities.common.texts import to_string


def system_platform() -> tuple[str, bool, bool]:
    """ Get OS platform """

    sys_os: str = platform.system()

    is_win: bool = sys_os == 'Windows'

    is_lnx: bool = sys_os in ('Linux', 'Darwin')

    return sys_os, is_win, is_lnx


def python_version() -> tuple:
    """ Get Python version """

    return sys.version_info


def printer(message: str | list | tuple | None = None, padding: int = 0, new_line: bool = True,
            pause: bool = False, sep_char: str = ' ') -> None:
    """ Show message(s), controlling padding, newline, pausing & separator """

    message_string: str = to_string(in_object='' if message is None else message, sep_char=sep_char)

    message_output: str = '\n' if new_line else ''

    for line_index, line_text in enumerate(iterable=message_string.split('\n')):
        line_newline: str = '' if line_index == 0 else '\n'

        message_output += f'{line_newline}{" " * padding}{line_text}'

    if pause:
        input(message_output)
    else:
        print(message_output)
