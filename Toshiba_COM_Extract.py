#!/usr/bin/env python3 -B
# coding=utf-8

"""
Toshiba COM Extract
Toshiba BIOS COM Extractor
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import os
import subprocess

from common.externals import get_comextract_path
from common.path_ops import make_dirs, path_stem, path_suffixes
from common.patterns import PAT_TOSHIBA_COM
from common.system import printer
from common.templates import BIOSUtility
from common.text_ops import file_to_bytes

TITLE = 'Toshiba BIOS COM Extractor v3.0'


def is_toshiba_com(in_file):
    """ Check if input is Toshiba BIOS COM image """

    buffer = file_to_bytes(in_file)

    is_ext = path_suffixes(in_file)[-1].upper() == '.COM' if os.path.isfile(in_file) else True

    is_com = PAT_TOSHIBA_COM.search(buffer)

    return is_ext and is_com


def toshiba_com_extract(input_file, extract_path, padding=0):
    """ Parse & Extract Toshiba BIOS COM image """

    if not os.path.isfile(input_file):
        printer('Error: Could not find input file path!', padding)

        return 1

    make_dirs(extract_path, delete=True)

    output_name = path_stem(input_file)

    output_file = os.path.join(extract_path, f'{output_name}.bin')

    try:
        subprocess.run([get_comextract_path(), input_file, output_file], check=True, stdout=subprocess.DEVNULL)

        if not os.path.isfile(output_file):
            raise ValueError('EXTRACT_FILE_MISSING')
    except Exception as error:  # pylint: disable=broad-except
        printer(f'Error: ToshibaComExtractor could not extract file {input_file}: {error}!', padding)

        return 2

    printer(f'Succesfull {output_name} extraction via ToshibaComExtractor!', padding)

    return 0


if __name__ == '__main__':
    BIOSUtility(title=TITLE, check=is_toshiba_com, main=toshiba_com_extract).run_utility()
