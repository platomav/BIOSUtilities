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

from collections import defaultdict
from re import Match
from typing import Any, Final

from biosutilities.common.externals import uefiextract_path, uefifind_path
from biosutilities.common.paths import delete_dirs, delete_file, is_access, is_file, path_suffixes, runtime_root
from biosutilities.common.patterns import PAT_INTEL_IBIOSI, PAT_APPLE_ROM_VER
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
        return struct.pack('B' * len(field), *field).decode('utf-16', 'ignore').strip('\x00 ')

    def get_bios_id(self) -> dict[str, str]:
        """ Get Apple/Intel EFI BIOS ID """

        intel_sig: str = self.Signature.decode('utf-8')

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

        efi_name_id: str = (f'{board_id}_{board_ext}_{version_major}_{build_type}{version_minor}'
                            f'_20{build_year}-{build_month}-{build_day}_{build_hour}-{build_minute}')

        return {
            'intel_sig': intel_sig,
            'board_id': board_id,
            'board_ext': board_ext,
            'version_major': version_major,
            'version_minor': version_minor,
            'build_type': build_type,
            'build_year': build_year,
            'build_month': build_month,
            'build_day': build_day,
            'build_hour': build_hour,
            'build_minute': build_minute,
            'efi_name_id': efi_name_id
        }

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        ibiosi: dict[str, str] = self.get_bios_id()

        ibiosi_date: str = f'20{ibiosi["build_year"]}-{ibiosi["build_month"]}-{ibiosi["build_day"]}'
        ibiosi_time: str = f'{ibiosi["build_hour"]}:{ibiosi["build_minute"]}'

        printer(message=['Intel Signature:', ibiosi['intel_sig']], padding=padding, new_line=False)
        printer(message=['Board Identity: ', ibiosi['board_id']], padding=padding, new_line=False)
        printer(message=['Apple Identity: ', ibiosi['board_ext']], padding=padding, new_line=False)
        printer(message=['Major Version:  ', ibiosi['version_major']], padding=padding, new_line=False)
        printer(message=['Minor Version:  ', ibiosi['version_minor']], padding=padding, new_line=False)
        printer(message=['Build Type:     ', ibiosi['build_type']], padding=padding, new_line=False)
        printer(message=['Build Date:     ', ibiosi_date], padding=padding, new_line=False)
        printer(message=['Build Time:     ', ibiosi_time], padding=padding, new_line=False)


class AppleEfiIdentify(BIOSUtility):
    """ Apple EFI Image Identifier """

    TITLE: str = 'Apple EFI Image Identifier'

    ARGUMENTS: list[tuple[list[str], dict[str, str]]] = [
        (['-q', '--silent'], {'help': 'suppress structure display', 'action': 'store_true'})
    ]

    PAT_UEFIFIND: Final[str] = f'244942494F534924{"." * 32}2E00{"." * 12}2E00{"." * 16}2E00{"." * 12}2E00{"." * 40}00'

    def __init__(self, arguments: list[str] | None = None) -> None:
        super().__init__(arguments=arguments)

        self.efi_file_name: str = ''
        self.intel_bios_info: dict[str, str] = {}
        self.apple_rom_version: defaultdict[str, set] = defaultdict(set)

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Apple EFI image """

        if isinstance(input_object, str) and is_file(in_path=input_object) and is_access(in_path=input_object):
            if path_suffixes(in_path=input_object)[-1].lower() not in ('.fd', '.scap', '.im4p'):
                return False

            input_path: str = input_object
            input_buffer: bytes = file_to_bytes(in_object=input_path)
        elif isinstance(input_object, (bytes, bytearray)):
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_ID_INPUT_BUFFER_CHECK.tmp')
            input_buffer = input_object

            with open(input_path, 'wb') as check_out:
                check_out.write(input_buffer)
        else:
            return False

        try:
            if PAT_INTEL_IBIOSI.search(input_buffer):
                return True

            _ = subprocess.run([uefifind_path(), input_path, 'body', 'list', self.PAT_UEFIFIND],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            return True
        except Exception as error:  # pylint: disable=broad-except
            logging.debug('Error: Could not check if input is Apple EFI image: %s', error)

            return False
        finally:
            if input_path != input_object:
                delete_file(in_path=input_path)

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool:
        """ Parse & Identify (or Rename) Apple EFI image """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        if isinstance(input_object, str) and is_file(in_path=input_object):
            input_path: str = input_object
        else:
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_ID_INPUT_BUFFER_PARSE.bin')

            with open(input_path, 'wb') as parse_out:
                parse_out.write(input_buffer)

        bios_id_match: Match[bytes] | None = PAT_INTEL_IBIOSI.search(input_buffer)

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

                with open(os.path.join(extract_path, 'body.bin'), 'rb') as raw_body:
                    body_buffer: bytes = raw_body.read()

                # Detect decompressed $IBIOSI$ pattern
                bios_id_match = PAT_INTEL_IBIOSI.search(body_buffer)

                if not bios_id_match:
                    raise RuntimeError('Failed to detect decompressed $IBIOSI$ pattern!')

                bios_id_hdr = ctypes_struct(buffer=body_buffer, start_offset=bios_id_match.start(),
                                            class_object=IntelBiosId)

                delete_dirs(in_path=extract_path)  # Successful UEFIExtract extraction, remove its output folder
            except Exception as error:  # pylint: disable=broad-except
                printer(message=f'Error: Failed to parse compressed $IBIOSI$ pattern: {error}!', padding=padding)

                return False

        if not self.arguments.silent:
            printer(message=f'Detected Intel BIOS Info at {bios_id_res}\n', padding=padding)

            bios_id_hdr.struct_print(padding=padding + 4)

        self.intel_bios_info = bios_id_hdr.get_bios_id()

        self.efi_file_name = (f'{self.intel_bios_info["efi_name_id"]}_{zlib.adler32(input_buffer):08X}'
                              f'{path_suffixes(in_path=input_path)[-1]}')

        _ = self._apple_rom_version(input_buffer=input_buffer, padding=padding)

        if input_path != input_object:
            delete_file(in_path=input_path)

        return True

    def _apple_rom_version(self, input_buffer: bytes | bytearray, padding: int = 0) -> bool:
        rom_version_match: Match[bytes] | None = PAT_APPLE_ROM_VER.search(input_buffer)

        if rom_version_match:
            rom_version_match_off: int = rom_version_match.start()

            rom_version_header_len: int = input_buffer[rom_version_match_off:].find(b'\n')

            if rom_version_header_len != -1:
                rom_version_data_bgn: int = rom_version_match_off + rom_version_header_len

                rom_version_data_len: int = input_buffer[rom_version_data_bgn:].find(b'\x00')

                if rom_version_data_len != -1:
                    rom_version_data_end: int = rom_version_data_bgn + rom_version_data_len

                    rom_version_data: bytes = input_buffer[rom_version_data_bgn:rom_version_data_end]

                    rom_version_text: str = rom_version_data.decode('utf-8').strip('\n')

                    for rom_version_line in [line.strip() for line in rom_version_text.split('\n')]:
                        rom_version_parts: list[str] = rom_version_line.split(sep=':', maxsplit=1)

                        self.apple_rom_version[rom_version_parts[0].strip()].add(rom_version_parts[1].strip())

                    if not self.arguments.silent:
                        printer(message=f'Detected Apple ROM Version at 0x{rom_version_match_off:X}', padding=padding)

                        printer(message=rom_version_text, strip=True, padding=padding + 4)

                    return True

        return False


if __name__ == '__main__':
    AppleEfiIdentify().run_utility()
