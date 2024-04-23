#!/usr/bin/env python3 -B
# coding=utf-8

"""
Fujitsu UPC Extract
Fujitsu UPC BIOS Extractor
Copyright (C) 2021-2024 Plato Mavropoulos
"""

import os

from common.comp_efi import efi_decompress, is_efi_compressed
from common.path_ops import make_dirs, path_suffixes
from common.templates import BIOSUtility
from common.text_ops import file_to_bytes

TITLE = 'Fujitsu UPC BIOS Extractor v3.0'


def is_fujitsu_upc(in_file):
    """ Check if input is Fujitsu UPC image """

    in_buffer = file_to_bytes(in_file)

    is_ext = path_suffixes(in_file)[-1].upper() == '.UPC' if os.path.isfile(in_file) else True

    is_efi = is_efi_compressed(in_buffer)

    return is_ext and is_efi


def fujitsu_upc_extract(input_file, extract_path, padding=0):
    """ Parse & Extract Fujitsu UPC image """

    make_dirs(extract_path, delete=True)

    image_base = os.path.basename(input_file)

    image_name = image_base[:-4] if image_base.upper().endswith('.UPC') else image_base

    image_path = os.path.join(extract_path, f'{image_name}.bin')

    return efi_decompress(input_file, image_path, padding)


if __name__ == '__main__':
    BIOSUtility(title=TITLE, check=is_fujitsu_upc, main=fujitsu_upc_extract).run_utility()
