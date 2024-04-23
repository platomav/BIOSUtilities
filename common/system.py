#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import sys

from common.text_ops import padder, to_string


def get_py_ver():
    """ Get Python Version (tuple) """

    return sys.version_info


def get_os_ver():
    """ Get OS Platform (string) """

    sys_os = sys.platform

    is_win = sys_os == 'win32'

    is_lnx = sys_os.startswith('linux') or sys_os == 'darwin' or sys_os.find('bsd') != -1

    return sys_os, is_win, is_win or is_lnx


def is_auto_exit():
    """ Check for --auto-exit|-e """

    return bool('--auto-exit' in sys.argv or '-e' in sys.argv)


def check_sys_py():
    """ # Check Python Version """

    sys_py = get_py_ver()

    if sys_py < (3, 10):
        sys.stdout.write(f'\nError: Python >= 3.10 required, not {sys_py[0]}.{sys_py[1]}!')

        if not is_auto_exit():
            # noinspection PyUnresolvedReferences
            (raw_input if sys_py[0] <= 2 else input)('\nPress enter to exit')  # pylint: disable=E0602

        sys.exit(125)


def check_sys_os():
    """ Check OS Platform """

    os_tag, os_win, os_sup = get_os_ver()

    if not os_sup:
        printer(f'Error: Unsupported platform "{os_tag}"!')

        if not is_auto_exit():
            input('\nPress enter to exit')

        sys.exit(126)

    # Fix Windows Unicode console redirection
    if os_win:
        # noinspection PyUnresolvedReferences
        sys.stdout.reconfigure(encoding='utf-8')


def printer(message=None, padd=0, new_line=True, pause=False, sep_char=' '):
    """ Show message(s), controlling padding, newline, pausing & separator """

    message_input = '' if message is None else message

    string = to_string(message_input, sep_char)

    padding = padder(padd)

    newline = '\n' if new_line else ''

    message_output = newline + padding + string

    (input if pause and not is_auto_exit() else print)(message_output)
