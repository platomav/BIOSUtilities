#!/usr/bin/env python3 -B
# coding=utf-8

"""
Portwell EFI Extract
Portwell EFI Update Extractor
Copyright (C) 2021-2024 Plato Mavropoulos
"""

import logging
import os

from re import Match
from typing import Final

from pefile import PE

from biosutilities.common.compression import efi_decompress, is_efi_compressed
from biosutilities.common.paths import make_dirs, safe_name
from biosutilities.common.executables import ms_pe
from biosutilities.common.patterns import PAT_MICROSOFT_MZ, PAT_PORTWELL_EFI
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class PortwellEfiExtract(BIOSUtility):
    """ Portwell EFI Update Extractor """

    TITLE: str = 'Portwell EFI Update Extractor'

    FILE_NAMES: Final[dict[int, str]] = {
        0: 'Flash.efi',
        1: 'Fparts.txt',
        2: 'Update.nsh',
        3: 'Temp.bin',
        4: 'SaveDmiData.efi'
    }

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Portwell EFI executable """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        try:
            pe_buffer: bytes = self._get_portwell_pe(in_buffer=input_buffer)[1]
        except Exception as error:  # pylint: disable=broad-except
            logging.debug('Error: Could not check if input is Portwell EFI executable: %s', error)

            return False

        # EFI images start with PE Header MZ
        if PAT_MICROSOFT_MZ.search(string=input_buffer[:0x2]):
            # Portwell EFI files start with <UU>
            if PAT_PORTWELL_EFI.search(string=pe_buffer[:0x4]):
                return True

        return False

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool:
        """ Parse & Extract Portwell UEFI Unpacker """

        # Initialize EFI Payload file chunks
        efi_files: list[bytes] = []

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        make_dirs(in_path=extract_path, delete=True)

        pe_file, pe_data = self._get_portwell_pe(in_buffer=input_buffer)

        efi_title: str = self._get_unpacker_tag(input_buffer=input_buffer, pe_file=pe_file)

        printer(message=efi_title, padding=padding)

        # Split EFI Payload into <UU> file chunks
        efi_list: list[Match[bytes]] = list(PAT_PORTWELL_EFI.finditer(string=pe_data))

        for idx, val in enumerate(iterable=efi_list):
            efi_bgn: int = val.end()
            efi_end: int = len(pe_data) if idx == len(efi_list) - 1 else efi_list[idx + 1].start()

            efi_files.append(pe_data[efi_bgn:efi_end])

        self._parse_efi_files(extract_path=extract_path, efi_files=efi_files, padding=padding)

        return True

    @staticmethod
    def _get_portwell_pe(in_buffer: bytes) -> tuple:
        """ Get PE of Portwell EFI executable """

        # Analyze EFI Portable Executable (PE)
        pe_file: PE | None = ms_pe(in_buffer, silent=True)

        # Skip EFI executable
        # pylint: disable=no-member
        pe_data: bytes = in_buffer[pe_file.OPTIONAL_HEADER.SizeOfImage:]  # type: ignore

        return pe_file, pe_data

    @staticmethod
    def _get_unpacker_tag(input_buffer: bytes | bytearray, pe_file: PE) -> str:
        """ Get Portwell UEFI Unpacker tag """

        unpacker_tag_txt: str = 'UEFI Unpacker'

        for pe_section in pe_file.sections:
            # Unpacker Tag, Version, Strings etc. are found in .data PE section
            if pe_section.Name.startswith(b'.data'):
                pe_data_bgn: int = pe_section.PointerToRawData
                pe_data_end: int = pe_data_bgn + pe_section.SizeOfRawData

                # Decode any valid UTF-16 .data PE section info to a parsable text buffer
                pe_data_txt: str = input_buffer[pe_data_bgn:pe_data_end].decode(encoding='utf-16', errors='ignore')

                # Search .data for UEFI Unpacker tag
                unpacker_tag_bgn: int = pe_data_txt.find(unpacker_tag_txt)

                if unpacker_tag_bgn != -1:
                    unpacker_tag_len: int = pe_data_txt[unpacker_tag_bgn:].find('=')

                    if unpacker_tag_len != -1:
                        unpacker_tag_end: int = unpacker_tag_bgn + unpacker_tag_len
                        unpacker_tag_raw: str = pe_data_txt[unpacker_tag_bgn:unpacker_tag_end]

                        # Found full UEFI Unpacker tag, store and slightly beautify the resulting text
                        unpacker_tag_txt = unpacker_tag_raw.strip().replace('   ', ' ').replace('<', ' <')

                break  # Found PE .data section, skip the rest

        return unpacker_tag_txt

    def _parse_efi_files(self, extract_path: str, efi_files: list[bytes], padding: int) -> None:
        """ Process Portwell UEFI Unpacker payload files """

        for file_index, file_data in enumerate(efi_files):
            if file_data in (b'', b'NULL'):
                continue  # Skip empty/unused files

            # Assign Name to EFI file
            file_name: str = self.FILE_NAMES.get(file_index, f'Unknown_{file_index}.bin')

            # Print EFI file name, indicate progress
            printer(message=f'[{file_index}] {file_name}', padding=padding + 4)

            if file_name.startswith('Unknown_'):
                printer(message=f'Note: Detected new Portwell EFI file ID {file_index}!',
                        padding=padding + 8, pause=True)

            # Store EFI file output path
            file_path: str = os.path.join(extract_path, safe_name(in_name=file_name))

            # Store EFI file data to drive
            with open(file=file_path, mode='wb') as out_file:
                out_file.write(file_data)

            # Attempt to detect EFI compression & decompress when applicable
            if is_efi_compressed(data=file_data):
                # Store temporary compressed file name
                comp_fname: str = file_path + '.temp'

                # Rename initial/compressed file
                os.replace(src=file_path, dst=comp_fname)

                # Successful decompression, delete compressed file
                if efi_decompress(in_path=comp_fname, out_path=file_path, padding=padding + 8):
                    os.remove(path=comp_fname)


if __name__ == '__main__':
    PortwellEfiExtract().run_utility()
