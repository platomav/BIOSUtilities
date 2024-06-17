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
from common.path_ops import make_dirs, path_stem, safe_name
from common.patterns import PAT_TOSHIBA_COM
from common.system import printer
from common.templates import BIOSUtility
from common.text_ops import file_to_bytes

TITLE = 'Toshiba BIOS COM Extractor v4.0'


def is_toshiba_com(input_object: str | bytes | bytearray) -> bool:
    """ Check if input is Toshiba BIOS COM image """

    return bool(PAT_TOSHIBA_COM.search(file_to_bytes(input_object)))


def toshiba_com_extract(input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> int:
    """ Parse & Extract Toshiba BIOS COM image """

    make_dirs(extract_path, delete=True)

    if isinstance(input_object, str) and os.path.isfile(input_object):
        input_path: str = input_object
    else:
        input_path = os.path.join(extract_path, 'toshiba_bios.com')

        with open(input_path, 'wb') as input_buffer:
            input_buffer.write(file_to_bytes(input_object))

    output_path: str = os.path.join(extract_path, f'{safe_name(path_stem(input_path))}_extracted.bin')

    try:
        subprocess.run([get_comextract_path(), input_path, output_path], check=True, stdout=subprocess.DEVNULL)

        if not os.path.isfile(output_path):
            raise FileNotFoundError('EXTRACTED_FILE_MISSING')
    except Exception as error:  # pylint: disable=broad-except
        printer(f'Error: ToshibaComExtractor could not extract {input_path}: {error}!', padding)

        return 1

    printer('Succesfull extraction via ToshibaComExtractor!', padding)

    return 0


if __name__ == '__main__':
    BIOSUtility(title=TITLE, check=is_toshiba_com, main=toshiba_com_extract).run_utility()
