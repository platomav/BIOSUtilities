#!/usr/bin/env python3 -B
# coding=utf-8

"""
Fujitsu UPC Extract
Fujitsu UPC BIOS Extractor
Copyright (C) 2021-2024 Plato Mavropoulos
"""

import os

from biosutilities.common.compression import efi_decompress, is_efi_compressed
from biosutilities.common.paths import make_dirs, is_file, path_name, path_suffixes
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class FujitsuUpcExtract(BIOSUtility):
    """ Fujitsu UPC BIOS Extractor """

    TITLE: str = 'Fujitsu UPC BIOS Extractor'

    def check_format(self) -> bool:
        """ Check if input is Fujitsu UPC image """
        is_upc: bool = False

        if isinstance(self.input_object, str) and is_file(in_path=self.input_object):
            is_upc = path_suffixes(self.input_object)[-1].upper() == '.UPC'
        elif isinstance(self.input_object, (bytes, bytearray)):
            is_upc = True

        if is_upc:
            is_upc = is_efi_compressed(data=file_to_bytes(in_object=self.input_object))

        return is_upc

    def parse_format(self) -> bool:
        """ Parse & Extract Fujitsu UPC image """

        make_dirs(in_path=self.extract_path, delete=True)

        if isinstance(self.input_object, str) and is_file(in_path=self.input_object):
            input_name: str = path_name(in_path=self.input_object)

            input_path: str = self.input_object

            if input_name.upper().endswith('.UPC'):
                input_name = input_name[:-4]
        else:
            input_name = 'Fujitsu_UPC_Image'

            input_path = os.path.join(self.extract_path, f'{input_name}.UPC')

            with open(input_path, 'wb') as input_path_object:
                input_path_object.write(file_to_bytes(in_object=self.input_object))

        output_path: str = os.path.join(self.extract_path, f'{input_name}.bin')

        efi_status: bool = efi_decompress(in_path=input_path, out_path=output_path, padding=self.padding)

        if input_path != self.input_object:
            os.remove(input_path)

        return efi_status
