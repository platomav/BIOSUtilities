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

from re import Match
from typing import Any, Final

from biosutilities.common.externals import uefiextract_path, uefifind_path
from biosutilities.common.paths import delete_dirs, delete_file, path_suffixes, runtime_root
from biosutilities.common.patterns import PAT_APPLE_EFI
from biosutilities.common.structs import CHAR, ctypes_struct, UINT8
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class IntelBiosId(ctypes.LittleEndianStructure):
    """
    Intel BIOS ID Structure

    https://github.com/tianocore/edk2-platforms/blob/master/Platform/Intel/BoardModulePkg/Include/Guid/BiosId.h
    """

    _pack_ = 1
    _fields_ = [
        ('Signature',       CHAR * 8),      # 0x00
        ('BoardID',         UINT8 * 16),    # 0x08
        ('Dot1',            UINT8 * 2),     # 0x18
        ('BoardExt',        UINT8 * 6),     # 0x1A
        ('Dot2',            UINT8 * 2),     # 0x20
        ('VersionMajor',    UINT8 * 8),     # 0x22
        ('Dot3',            UINT8 * 2),     # 0x2A
        ('BuildType',       UINT8 * 2),     # 0x2C
        ('VersionMinor',    UINT8 * 4),     # 0x2E
        ('Dot4',            UINT8 * 2),     # 0x32
        ('Year',            UINT8 * 4),     # 0x34
        ('Month',           UINT8 * 4),     # 0x38
        ('Day',             UINT8 * 4),     # 0x3C
        ('Hour',            UINT8 * 4),     # 0x40
        ('Minute',          UINT8 * 4),     # 0x44
        ('NullTerminator',  UINT8 * 2)      # 0x48
        # 0x4A
    ]

    @staticmethod
    def _decode(field: bytes) -> str:
        return struct.pack('B' * len(field), *field).decode(encoding='utf-16', errors='ignore').strip('\x00 ')

    def get_bios_id(self) -> tuple:
        """ Create Apple EFI BIOS ID """

        board_id: str = self._decode(field=self.BoardID)
        board_ext: str = self._decode(field=self.BoardExt)
        version_major: str = self._decode(field=self.VersionMajor)
        build_type: str = self._decode(field=self.BuildType)
        version_minor: str = self._decode(field=self.VersionMinor)
        build_year: str = self._decode(field=self.Year)
        build_month: str = self._decode(field=self.Month)
        build_day: str = self._decode(field=self.Day)
        build_hour: str = self._decode(field=self.Hour)
        build_minute: str = self._decode(field=self.Minute)

        build_date: str = f'20{build_year}-{build_month}-{build_day}'
        build_time: str = f'{build_hour}-{build_minute}'

        return board_id, board_ext, version_major, build_type, version_minor, build_date, build_time

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        board_id, board_ext, version_major, build_type, version_minor, build_date, build_time = self.get_bios_id()

        intel_id: str = self.Signature.decode(encoding='utf-8')

        printer(message=['Intel Signature:', intel_id], padding=padding, new_line=False)
        printer(message=['Board Identity: ', board_id], padding=padding, new_line=False)
        printer(message=['Apple Identity: ', board_ext], padding=padding, new_line=False)
        printer(message=['Major Version:  ', version_major], padding=padding, new_line=False)
        printer(message=['Minor Version:  ', version_minor], padding=padding, new_line=False)
        printer(message=['Build Type:     ', build_type], padding=padding, new_line=False)
        printer(message=['Build Date:     ', build_date], padding=padding, new_line=False)
        printer(message=['Build Time:     ', build_time.replace('-', ':')], padding=padding, new_line=False)


class AppleEfiIdentify(BIOSUtility):
    """ Apple EFI Image Identifier """

    TITLE: str = 'Apple EFI Image Identifier'

    PAT_UEFIFIND: Final[str] = f'244942494F534924{"." * 32}2E00{"." * 12}2E00{"." * 16}2E00{"." * 12}2E00{"." * 40}0000'

    def __init__(self, arguments: list[str] | None = None) -> None:
        super().__init__(arguments=arguments)

        self.efi_name_id: str = ''

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Apple EFI image """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        if PAT_APPLE_EFI.search(string=input_buffer):
            return True

        if isinstance(input_object, str) and os.path.isfile(path=input_object):
            input_path: str = input_object
        else:
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_ID_INPUT_BUFFER_CHECK.tmp')

            with open(file=input_path, mode='wb') as check_out:
                check_out.write(input_buffer)

        try:
            _ = subprocess.run([uefifind_path(), input_path, 'body', 'list', self.PAT_UEFIFIND],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            return True
        except Exception as error:  # pylint: disable=broad-except
            logging.debug('Error: Could not check if input is Apple EFI image: %s', error)

            return False
        finally:
            if input_path != input_object:
                delete_file(in_path=input_path)

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> int:
        """ Parse & Identify (or Rename) Apple EFI image """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        if isinstance(input_object, str) and os.path.isfile(path=input_object):
            input_path: str = input_object
        else:
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_ID_INPUT_BUFFER_PARSE.bin')

            with open(file=input_path, mode='wb') as parse_out:
                parse_out.write(input_buffer)

        bios_id_match: Match[bytes] | None = PAT_APPLE_EFI.search(string=input_buffer)

        if bios_id_match:
            bios_id_res: str = f'0x{bios_id_match.start():X}'

            bios_id_hdr: Any = ctypes_struct(buffer=input_buffer, start_offset=bios_id_match.start(),
                                             class_object=IntelBiosId)
        else:
            # The $IBIOSI$ pattern is within EFI compressed modules so we need to use UEFIFind and UEFIExtract
            try:
                bios_id_res = subprocess.check_output([uefifind_path(), input_path, 'body', 'list',
                                                       self.PAT_UEFIFIND], text=True)[:36]

                # UEFIExtract must create its output folder itself
                delete_dirs(in_path=extract_path)

                _ = subprocess.run([uefiextract_path(), input_path, bios_id_res, '-o', extract_path, '-m', 'body'],
                                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                with open(file=os.path.join(extract_path, 'body.bin'), mode='rb') as raw_body:
                    body_buffer: bytes = raw_body.read()

                # Detect decompressed $IBIOSI$ pattern
                bios_id_match = PAT_APPLE_EFI.search(string=body_buffer)

                if not bios_id_match:
                    raise RuntimeError('Failed to detect decompressed $IBIOSI$ pattern!')

                bios_id_hdr = ctypes_struct(buffer=body_buffer, start_offset=bios_id_match.start(),
                                            class_object=IntelBiosId)

                delete_dirs(in_path=extract_path)  # Successful UEFIExtract extraction, remove its output folder
            except Exception as error:  # pylint: disable=broad-except
                printer(message=f'Error: Failed to parse compressed $IBIOSI$ pattern: {error}!', padding=padding)

                return 1

        printer(message=f'Detected $IBIOSI$ at {bios_id_res}\n', padding=padding)

        bios_id_hdr.struct_print(padding=padding + 4)

        input_suffix: str = path_suffixes(input_path)[-1]

        input_adler32: int = zlib.adler32(input_buffer)

        fw_id, fw_ext, fw_major, fw_type, fw_minor, fw_date, fw_time = bios_id_hdr.get_bios_id()

        self.efi_name_id = (f'{fw_id}_{fw_ext}_{fw_major}_{fw_type}{fw_minor}_{fw_date}_{fw_time}_'
                            f'{input_adler32:08X}{input_suffix}')

        if input_path != input_object:
            delete_file(in_path=input_path)

        return 0


if __name__ == '__main__':
    AppleEfiIdentify().run_utility()
