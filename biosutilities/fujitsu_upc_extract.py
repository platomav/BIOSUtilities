#!/usr/bin/env python3 -B
# coding=utf-8

"""
Fujitsu UPC Extract
Fujitsu UPC BIOS Extractor
Copyright (C) 2021-2024 Plato Mavropoulos
"""

import os

from biosutilities.common.compression import efi_decompress, is_efi_compressed
from biosutilities.common.paths import make_dirs, path_name, path_suffixes
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class FujitsuUpcExtract(BIOSUtility):
    """ Fujitsu UPC BIOS Extractor """

    TITLE: str = 'Fujitsu UPC BIOS Extractor'

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Fujitsu UPC image """
        is_upc: bool = False

        if isinstance(input_object, str) and os.path.isfile(path=input_object):
            is_upc = path_suffixes(input_object)[-1].upper() == '.UPC'
        elif isinstance(input_object, (bytes, bytearray)):
            is_upc = True

        if is_upc:
            is_upc = is_efi_compressed(data=file_to_bytes(in_object=input_object))

        return is_upc

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool:
        """ Parse & Extract Fujitsu UPC image """

        make_dirs(in_path=extract_path, delete=True)

        if isinstance(input_object, str) and os.path.isfile(path=input_object):
            input_name: str = path_name(in_path=input_object)

            input_path: str = input_object

            if input_name.upper().endswith('.UPC'):
                input_name = input_name[:-4]
        else:
            input_name = 'Fujitsu_UPC_Image'

            input_path = os.path.join(extract_path, f'{input_name}.UPC')

            with open(file=input_path, mode='wb') as input_path_object:
                input_path_object.write(file_to_bytes(in_object=input_object))

        output_path: str = os.path.join(extract_path, f'{input_name}.bin')

        efi_status: bool = efi_decompress(in_path=input_path, out_path=output_path, padding=padding)

        if input_path != input_object:
            os.remove(path=input_path)

        return efi_status


if __name__ == '__main__':
    FujitsuUpcExtract().run_utility()
