#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import os
import subprocess

from common.externals import get_tiano_path
from common.system import printer


def get_compress_sizes(data):
    """ Get EFI compression sizes """

    size_compress = int.from_bytes(data[0x0:0x4], 'little')
    size_original = int.from_bytes(data[0x4:0x8], 'little')

    return size_compress, size_original


def is_efi_compressed(data, strict=True):
    """ Check if data is EFI compressed, controlling EOF padding """

    size_comp, size_orig = get_compress_sizes(data)

    check_diff = size_comp < size_orig

    if strict:
        check_size = size_comp + 0x8 == len(data)
    else:
        check_size = size_comp + 0x8 <= len(data)

    return check_diff and check_size


def efi_decompress(in_path, out_path, padding=0, silent=False, comp_type='--uefi'):
    """ EFI/Tiano Decompression via TianoCompress """

    try:
        subprocess.run([get_tiano_path(), '-d', in_path, '-o', out_path, '-q', comp_type],
                       check=True, stdout=subprocess.DEVNULL)

        with open(in_path, 'rb') as file:
            _, size_orig = get_compress_sizes(file.read())

        if os.path.getsize(out_path) != size_orig:
            raise OSError('EFI decompressed file & header size mismatch!')
    except Exception as error:  # pylint: disable=broad-except
        if not silent:
            printer(f'Error: TianoCompress could not extract file {in_path}: {error}!', padding)

        return 1

    if not silent:
        printer('Succesfull EFI decompression via TianoCompress!', padding)

    return 0
