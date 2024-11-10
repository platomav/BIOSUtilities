#!/usr/bin/env python3 -B
# coding=utf-8

"""
Toshiba COM Extract
Toshiba BIOS COM Extractor
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import os
import subprocess

from biosutilities.common.externals import comextract_path
from biosutilities.common.paths import delete_file, is_file_read, make_dirs, path_stem
from biosutilities.common.patterns import PAT_TOSHIBA_COM
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility


class ToshibaComExtract(BIOSUtility):
    """ Toshiba BIOS COM Extractor """

    TITLE: str = 'Toshiba BIOS COM Extractor'

    def check_format(self) -> bool:
        """ Check if input is Toshiba BIOS COM image """

        if isinstance(self.input_object, str) and is_file_read(in_path=self.input_object):
            with open(self.input_object, 'rb') as input_object:
                check_buffer: bytes = input_object.read(0x100)
        else:
            check_buffer = self.input_buffer[:0x100]

        return bool(PAT_TOSHIBA_COM.search(check_buffer, 0, 0x100))

    def parse_format(self) -> bool:
        """ Parse & Extract Toshiba BIOS COM image """

        make_dirs(in_path=self.extract_path)

        if isinstance(self.input_object, str) and is_file_read(in_path=self.input_object):
            input_path: str = self.input_object
        else:
            input_path = os.path.join(self.extract_path, 'toshiba_bios.com')

            with open(input_path, 'wb') as input_buffer:
                input_buffer.write(self.input_buffer)

        output_path: str = os.path.join(self.extract_path, f'{path_stem(in_path=input_path)}_extracted.bin')

        comextract_res: subprocess.CompletedProcess[bytes] = subprocess.run(
            [comextract_path(), input_path, output_path], check=False, stdout=subprocess.DEVNULL)

        if input_path != self.input_object:
            delete_file(in_path=input_path)

        if comextract_res.returncode == 0 and is_file_read(in_path=output_path):
            printer(message='Successful extraction via ToshibaComExtractor!', padding=self.padding)

            return True

        return False
