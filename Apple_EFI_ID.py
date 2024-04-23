#!/usr/bin/env python3 -B
# coding=utf-8

"""
Apple EFI ID
Apple EFI Image Identifier
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import ctypes
import logging
import os
import struct
import subprocess
import zlib

from common.externals import get_uefiextract_path, get_uefifind_path
from common.path_ops import del_dirs, path_parent, path_suffixes
from common.patterns import PAT_APPLE_EFI
from common.struct_ops import Char, get_struct, UInt8
from common.system import printer
from common.templates import BIOSUtility
from common.text_ops import file_to_bytes

TITLE = 'Apple EFI Image Identifier v3.0'


class IntelBiosId(ctypes.LittleEndianStructure):
    """ Intel BIOS ID Structure """

    _pack_ = 1
    _fields_ = [
        ('Signature', Char * 8),  # 0x00
        ('BoardID', UInt8 * 16),  # 0x08
        ('Dot1', UInt8 * 2),  # 0x18
        ('BoardExt', UInt8 * 6),  # 0x1A
        ('Dot2', UInt8 * 2),  # 0x20
        ('VersionMajor', UInt8 * 8),  # 0x22
        ('Dot3', UInt8 * 2),  # 0x2A
        ('BuildType', UInt8 * 2),  # 0x2C
        ('VersionMinor', UInt8 * 4),  # 0x2E
        ('Dot4', UInt8 * 2),  # 0x32
        ('Year', UInt8 * 4),  # 0x34
        ('Month', UInt8 * 4),  # 0x38
        ('Day', UInt8 * 4),  # 0x3C
        ('Hour', UInt8 * 4),  # 0x40
        ('Minute', UInt8 * 4),  # 0x44
        ('NullTerminator', UInt8 * 2),  # 0x48
        # 0x4A
    ]

    # https://github.com/tianocore/edk2-platforms/blob/master/Platform/Intel/BoardModulePkg/Include/Guid/BiosId.h

    @staticmethod
    def _decode(field):
        return struct.pack('B' * len(field), *field).decode('utf-16', 'ignore').strip('\x00 ')

    def get_bios_id(self):
        """ Create Apple EFI BIOS ID """

        board_id = self._decode(self.BoardID)
        board_ext = self._decode(self.BoardExt)
        version_major = self._decode(self.VersionMajor)
        build_type = self._decode(self.BuildType)
        version_minor = self._decode(self.VersionMinor)
        build_date = f'20{self._decode(self.Year)}-{self._decode(self.Month)}-{self._decode(self.Day)}'
        build_time = f'{self._decode(self.Hour)}-{self._decode(self.Minute)}'

        return board_id, board_ext, version_major, build_type, version_minor, build_date, build_time

    def struct_print(self, padd):
        """ Display structure information """

        board_id, board_ext, version_major, build_type, version_minor, build_date, build_time = self.get_bios_id()

        printer(['Intel Signature:', self.Signature.decode('utf-8')], padd, False)
        printer(['Board Identity: ', board_id], padd, False)
        printer(['Apple Identity: ', board_ext], padd, False)
        printer(['Major Version:  ', version_major], padd, False)
        printer(['Minor Version:  ', version_minor], padd, False)
        printer(['Build Type:     ', build_type], padd, False)
        printer(['Build Date:     ', build_date], padd, False)
        printer(['Build Time:     ', build_time.replace('-', ':')], padd, False)


def is_apple_efi(input_file):
    """ Check if input is Apple EFI image """

    input_buffer = file_to_bytes(input_file)

    if PAT_APPLE_EFI.search(input_buffer):
        return True

    if not os.path.isfile(input_file):
        return False

    try:
        _ = subprocess.run([get_uefifind_path(), input_file, 'body', 'list', PAT_UEFIFIND],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return True
    except Exception as error:  # pylint: disable=broad-except
        logging.debug('Error: Could not check if input is Apple EFI image: %s', error)

        return False


def apple_efi_identify(input_file, extract_path, padding=0, rename=False):
    """ Parse & Identify (or Rename) Apple EFI image """

    if not os.path.isfile(input_file):
        printer('Error: Could not find input file path!', padding)

        return 1

    input_buffer = file_to_bytes(input_file)

    bios_id_match = PAT_APPLE_EFI.search(input_buffer)  # Detect $IBIOSI$ pattern

    if bios_id_match:
        bios_id_res = f'0x{bios_id_match.start():X}'

        bios_id_hdr = get_struct(input_buffer, bios_id_match.start(), IntelBiosId)
    else:
        # The $IBIOSI$ pattern is within EFI compressed modules so we need to use UEFIFind and UEFIExtract
        try:
            bios_id_res = subprocess.check_output([get_uefifind_path(), input_file, 'body', 'list', PAT_UEFIFIND],
                                                  text=True)[:36]

            del_dirs(extract_path)  # UEFIExtract must create its output folder itself, make sure it is not present

            _ = subprocess.run([get_uefiextract_path(), input_file, bios_id_res, '-o', extract_path, '-m', 'body'],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            with open(os.path.join(extract_path, 'body.bin'), 'rb') as raw_body:
                body_buffer = raw_body.read()

            bios_id_match = PAT_APPLE_EFI.search(body_buffer)  # Detect decompressed $IBIOSI$ pattern

            bios_id_hdr = get_struct(body_buffer, bios_id_match.start(), IntelBiosId)

            del_dirs(extract_path)  # Successful UEFIExtract extraction, remove its output (temp) folder
        except Exception as error:  # pylint: disable=broad-except
            printer(f'Error: Failed to parse compressed $IBIOSI$ pattern: {error}!', padding)

            return 2

    printer(f'Detected $IBIOSI$ at {bios_id_res}\n', padding)

    bios_id_hdr.struct_print(padding + 4)

    if rename:
        input_parent = path_parent(input_file)

        input_suffix = path_suffixes(input_file)[-1]

        input_adler32 = zlib.adler32(input_buffer)

        fw_id, fw_ext, fw_major, fw_type, fw_minor, fw_date, fw_time = bios_id_hdr.get_bios_id()

        output_name = f'{fw_id}_{fw_ext}_{fw_major}_{fw_type}{fw_minor}_{fw_date}_{fw_time}_' \
                      f'{input_adler32:08X}{input_suffix}'

        output_file = os.path.join(input_parent, output_name)

        if not os.path.isfile(output_file):
            os.replace(input_file, output_file)  # Rename input file based on its EFI tag

        printer(f'Renamed to {output_name}', padding)

    return 0


PAT_UEFIFIND = f'244942494F534924{"." * 32}2E00{"." * 12}2E00{"." * 16}2E00{"." * 12}2E00{"." * 40}0000'

if __name__ == '__main__':
    utility_args = [(['-r', '--rename'], {'help': 'rename EFI image based on its tag', 'action': 'store_true'})]

    utility = BIOSUtility(title=TITLE, check=is_apple_efi, main=apple_efi_identify, args=utility_args)

    utility.run_utility()
