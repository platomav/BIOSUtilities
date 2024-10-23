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
            sep_char: str = ' ', strip: bool = False) -> None:
    """ Show message(s), controlling padding, newline, stripping, pausing & separating """

    message_string: str = to_string(in_object='' if message is None else message, sep_char=sep_char)

    message_output: str = '\n' if new_line else ''

    for message_line_index, message_line_text in enumerate(message_string.split('\n')):
        line_new: str = '' if message_line_index == 0 else '\n'

        line_text: str = message_line_text.strip() if strip else message_line_text

        message_output += f'{line_new}{" " * padding}{line_text}'

    print(message_output)
