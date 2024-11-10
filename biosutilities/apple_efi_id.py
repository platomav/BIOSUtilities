#!/usr/bin/env python3 -B
# coding=utf-8

"""
Apple EFI ID
Apple EFI Image Identifier
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import ctypes
import os
import struct
import subprocess
import zlib

from datetime import datetime
from re import Match
from typing import Any, Final

from biosutilities.common.externals import uefiextract_path, uefifind_path
from biosutilities.common.paths import (delete_dirs, delete_file, is_file_read, make_dirs, path_size,
                                        path_suffixes, runtime_root)
from biosutilities.common.patterns import PAT_INTEL_IBIOSI, PAT_APPLE_ROM_VER
from biosutilities.common.structs import CHAR, ctypes_struct, UINT8
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility

EFI_EXTENSIONS: Final[list[str]] = ['.fd', '.scap', '.im4p']
EFI_MAX_SIZE: Final[int] = 0x3000000


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

        board_id: str = self._decode(field=self.BoardID)
        board_ext: str = self._decode(field=self.BoardExt)
        version_major: str = self._decode(field=self.VersionMajor)
        build_type: str = self._decode(field=self.BuildType)
        version_minor: str = self._decode(field=self.VersionMinor)
        build_year: int = int(f'20{self._decode(field=self.Year)}')
        build_month: int = int(self._decode(field=self.Month))
        build_day: int = int(self._decode(field=self.Day))
        build_hour: int = int(self._decode(field=self.Hour))
        build_minute: int = int(self._decode(field=self.Minute))

        efi_version: str = f'{version_major}_{build_type}{version_minor}'
        efi_date: datetime = datetime(build_year, build_month, build_day, build_hour, build_minute)
        efi_name: str = f'{board_id}_{board_ext}_{efi_version}_{efi_date.strftime("%Y-%m-%d_%H-%M")}'

        return {
            'board_id': board_id,
            'apple_id': board_ext,
            'version': efi_version,
            'date': efi_date.isoformat(),
            'name': efi_name
        }

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        ibiosi: dict[str, str] = self.get_bios_id()

        printer(message=['Board ID: ', ibiosi['board_id']], padding=padding, new_line=False)
        printer(message=['Apple ID: ', ibiosi['apple_id']], padding=padding, new_line=False)
        printer(message=['Version:  ', ibiosi['version']], padding=padding, new_line=False)
        printer(message=['Datetime: ', ibiosi['date']], padding=padding, new_line=False)


class AppleEfiIdentify(BIOSUtility):
    """ Apple EFI Image Identifier """

    TITLE: str = 'Apple EFI Image Identifier'

    PAT_UEFIFIND: Final[str] = f'244942494F534924{"." * 32}2E00{"." * 12}2E00{"." * 16}2E00{"." * 12}2E00{"." * 40}00'

    def __init__(self, input_object: str | bytes | bytearray = b'', extract_path: str = '', padding: int = 0,
                 silent: bool = False) -> None:
        super().__init__(input_object=input_object, extract_path=extract_path, padding=padding)

        self.silent: bool = silent

        self.efi_file_name: str = ''

        self.intel_bios_info: dict[str, str] = {
            'board_id': '',
            'apple_id': '',
            'version': '',
            'date': '',
            'name': ''
        }

        self.apple_rom_version: dict[str, str] = {
            'bios_id': '',
            'board_id': '',
            'build_type': '',
            'buildcave_id': '',
            'built_by': '',
            'compiler': '',
            'date': '',
            'efi_version': '',
            'model': '',
            'rom_version': '',
            'revision': '',
            'uuid': ''
        }

    def check_format(self) -> bool:
        """ Check if input is Apple EFI image """

        if isinstance(self.input_object, str) and is_file_read(in_path=self.input_object):
            if path_suffixes(in_path=self.input_object)[-1].lower() not in EFI_EXTENSIONS:
                return False

            if path_size(in_path=self.input_object) > EFI_MAX_SIZE:
                return False

            input_path: str = self.input_object
        else:
            if len(self.input_buffer) > EFI_MAX_SIZE:
                return False

            input_path = os.path.join(runtime_root(), 'APPLE_EFI_ID_INPUT_BUFFER_CHECK.tmp')

            with open(input_path, 'wb') as check_out:
                check_out.write(self.input_buffer)

        if PAT_INTEL_IBIOSI.search(self.input_buffer):
            return True

        uefifind_cmd: list[str] = [uefifind_path(), input_path, 'body', 'list', self.PAT_UEFIFIND]

        uefifind_res: subprocess.CompletedProcess[bytes] = subprocess.run(
            uefifind_cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if input_path != self.input_object:
            delete_file(in_path=input_path)

        if uefifind_res.returncode == 0:
            return True

        return False

    def parse_format(self) -> bool:
        """ Parse & Identify (or Rename) Apple EFI image """

        if isinstance(self.input_object, str) and is_file_read(in_path=self.input_object):
            input_path: str = self.input_object
        else:
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_ID_INPUT_BUFFER_PARSE.tmp')

            with open(input_path, 'wb') as parse_out:
                parse_out.write(self.input_buffer)

        bios_id_match: Match[bytes] | None = PAT_INTEL_IBIOSI.search(self.input_buffer)

        if bios_id_match:
            bios_id_res: str = f'0x{bios_id_match.start():X}'

            bios_id_hdr: Any = ctypes_struct(buffer=self.input_buffer, start_offset=bios_id_match.start(),
                                             class_object=IntelBiosId)
        else:
            # The $IBIOSI$ pattern is within EFI compressed modules so we need to use UEFIFind and UEFIExtract

            bios_id_res = subprocess.check_output([uefifind_path(), input_path, 'body', 'list',
                                                   self.PAT_UEFIFIND], text=True)[:36]

            make_dirs(in_path=self.extract_path)

            uefiextract_dir: str = os.path.join(self.extract_path, 'uefiextract_temp')

            # UEFIExtract must create its output folder itself
            delete_dirs(in_path=uefiextract_dir)

            _ = subprocess.run([uefiextract_path(), input_path, bios_id_res, '-o', uefiextract_dir, '-m', 'body'],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            with open(os.path.join(uefiextract_dir, 'body.bin'), 'rb') as raw_body:
                body_buffer: bytes = raw_body.read()

            # Detect decompressed $IBIOSI$ pattern
            bios_id_match = PAT_INTEL_IBIOSI.search(body_buffer)

            if not bios_id_match:
                raise RuntimeError('Failed to detect decompressed $IBIOSI$ pattern!')

            bios_id_hdr = ctypes_struct(buffer=body_buffer, start_offset=bios_id_match.start(),
                                        class_object=IntelBiosId)

            delete_dirs(in_path=uefiextract_dir)  # Successful UEFIExtract extraction, remove its output folder

        if not self.silent:
            printer(message=f'Detected Intel BIOS Info at {bios_id_res}\n', padding=self.padding)

            bios_id_hdr.struct_print(padding=self.padding + 4)

        self.intel_bios_info |= bios_id_hdr.get_bios_id()

        self.efi_file_name = (f'{self.intel_bios_info["name"]}_{zlib.adler32(self.input_buffer):08X}'
                              f'{path_suffixes(in_path=input_path)[-1]}')

        _ = self._apple_rom_version(input_buffer=self.input_buffer, padding=self.padding)

        if input_path != self.input_object:
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

                    if not self.silent:
                        printer(message=f'Detected Apple ROM Version at 0x{rom_version_match_off:X}', padding=padding)

                        printer(message=rom_version_text, strip=True, padding=padding + 4)

                    for rom_version_line in [line.strip() for line in rom_version_text.split('\n')]:
                        rom_version_parts: list[str] = rom_version_line.split(sep=':', maxsplit=1)

                        rom_version_key: str = rom_version_parts[0].strip().lower().replace(' ', '_')
                        rom_version_val: str = rom_version_parts[1].strip()

                        if rom_version_key == 'uuid':
                            if self.apple_rom_version[rom_version_key] == '':
                                self.apple_rom_version[rom_version_key] = rom_version_val
                            else:
                                self.apple_rom_version[rom_version_key] += f', {rom_version_val}'
                        elif rom_version_key == 'date':
                            self.apple_rom_version[rom_version_key] = datetime.strptime(rom_version_val.replace(
                                ' PDT', '').replace(' PST', ''), '%a %b %d %H:%M:%S %Y').isoformat()
                        else:
                            self.apple_rom_version[rom_version_key] = rom_version_val

                    return True

        return False
