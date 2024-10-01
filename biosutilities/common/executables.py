#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import pefile

from biosutilities.common.system import printer
from biosutilities.common.texts import file_to_bytes


def is_ms_pe(in_file: str | bytes) -> bool:
    """ Check if input is a PE file """

    return bool(ms_pe(in_file=in_file, silent=True))


def ms_pe(in_file: str | bytes, padding: int = 0, fast: bool = True, silent: bool = False) -> pefile.PE | None:
    """ Get pefile object from PE file """

    pe_file: pefile.PE | None = None

    try:
        # Analyze detected MZ > PE image buffer
        pe_file = pefile.PE(data=file_to_bytes(in_file), fast_load=fast)
    except Exception as error:  # pylint: disable=broad-except
        if not silent:
            filename: str = in_file if isinstance(in_file, str) else 'buffer'

            printer(message=f'Error: Could not get pefile object from {filename}: {error}!', padding=padding)

    return pe_file


def ms_pe_desc(pe_file: pefile.PE, padding: int = 0, silent: bool = False) -> bytes:
    """ Get PE description from pefile object info """

    return ms_pe_info(pe_file=pe_file, padding=padding, silent=silent).get(b'FileDescription', b'')


def ms_pe_info(pe_file: pefile.PE, padding: int = 0, silent: bool = False) -> dict:
    """ Get PE info from pefile object """

    pe_info: dict = {}

    try:
        # When fast_load is used, IMAGE_DIRECTORY_ENTRY_RESOURCE must be parsed prior to FileInfo > StringTable
        pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        # Retrieve MZ > PE > FileInfo > StringTable information
        pe_info = pe_file.FileInfo[0][0].StringTable[0].entries
    except Exception as error:  # pylint: disable=broad-except
        if not silent:
            printer(message=f'Error: Could not get PE info from pefile object: {error}!', padding=padding)

    return pe_info


def ms_pe_info_show(pe_file: pefile.PE, padding: int = 0) -> None:
    """ Print PE info from pefile StringTable """

    pe_info: dict = ms_pe_info(pe_file=pe_file, padding=padding)

    if isinstance(pe_info, dict):
        for title, value in pe_info.items():
            info_title: str = title.decode(encoding='utf-8', errors='ignore').strip()
            info_value: str = value.decode(encoding='utf-8', errors='ignore').strip()

            if info_title and info_value:
                printer(message=f'{info_title}: {info_value}', padding=padding, new_line=False)
