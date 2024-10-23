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
from biosutilities.common.paths import is_file, make_dirs, path_stem, safe_name
from biosutilities.common.patterns import PAT_TOSHIBA_COM
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class ToshibaComExtract(BIOSUtility):
    """ Toshiba BIOS COM Extractor """

    TITLE: str = 'Toshiba BIOS COM Extractor'

    def check_format(self) -> bool:
        """ Check if input is Toshiba BIOS COM image """

        input_buffer: bytes = file_to_bytes(in_object=self.input_object)

        return bool(PAT_TOSHIBA_COM.search(input_buffer, 0, 0x100))

    def parse_format(self) -> bool:
        """ Parse & Extract Toshiba BIOS COM image """

        make_dirs(in_path=self.extract_path, delete=True)

        if isinstance(self.input_object, str) and is_file(in_path=self.input_object):
            input_path: str = self.input_object
        else:
            input_path = os.path.join(self.extract_path, 'toshiba_bios.com')

            with open(input_path, 'wb') as input_buffer:
                input_buffer.write(file_to_bytes(in_object=self.input_object))

        output_name: str = f'{safe_name(in_name=path_stem(in_path=input_path))}_extracted.bin'

        output_path: str = os.path.join(self.extract_path, output_name)

        try:
            subprocess.run([comextract_path(), input_path, output_path], check=True, stdout=subprocess.DEVNULL)

            if not is_file(in_path=output_path):
                raise FileNotFoundError('EXTRACTED_FILE_MISSING')
        except Exception as error:  # pylint: disable=broad-except
            printer(message=f'Error: ToshibaComExtractor could not extract {input_path}: {error}!',
                    padding=self.padding)

            return False

        if input_path != self.input_object:
            os.remove(input_path)

        printer(message='Successful extraction via ToshibaComExtractor!', padding=self.padding)

        return True
