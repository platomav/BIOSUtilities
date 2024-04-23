#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import os
import subprocess

from common.externals import get_szip_path
from common.system import printer


def check_bad_exit_code(exit_code):
    """ Check 7-Zip bad exit codes (0 OK, 1 Warning) """

    if exit_code not in (0, 1):
        raise ValueError(f'Bad exit code: {exit_code}')


def is_szip_supported(in_path, padding=0, args=None, check=False, silent=False):
    """ Check if file is 7-Zip supported """

    try:
        if args is None:
            args = []

        szip_c = [get_szip_path(), 't', in_path, *args, '-bso0', '-bse0', '-bsp0']

        szip_t = subprocess.run(szip_c, check=False)

        if check:
            check_bad_exit_code(szip_t.returncode)
    except Exception as error:  # pylint: disable=broad-except
        if not silent:
            printer(f'Error: 7-Zip could not check support for file {in_path}: {error}!', padding)

        return False

    return True


def szip_decompress(in_path, out_path, in_name, padding=0, args=None, check=False, silent=False):
    """ Archive decompression via 7-Zip """

    if not in_name:
        in_name = 'archive'

    try:
        if args is None:
            args = []

        szip_c = [get_szip_path(), 'x', *args, '-aou', '-bso0', '-bse0', '-bsp0', f'-o{out_path}', in_path]

        szip_x = subprocess.run(szip_c, check=False)

        if check:
            check_bad_exit_code(szip_x.returncode)

        if not os.path.isdir(out_path):
            raise OSError(f'Extraction directory not found: {out_path}')
    except Exception as error:  # pylint: disable=broad-except
        if not silent:
            printer(f'Error: 7-Zip could not extract {in_name} file {in_path}: {error}!', padding)

        return 1

    if not silent:
        printer(f'Succesfull {in_name} decompression via 7-Zip!', padding)

    return 0
