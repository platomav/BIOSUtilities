#!/usr/bin/env python3 -B
# coding=utf-8

"""
Phoenix TDK Extract
Phoenix TDK Packer Extractor
Copyright (C) 2021-2024 Plato Mavropoulos
"""

import ctypes
import logging
import lzma
import os

from re import Match
from typing import Any, Final

from pefile import PE

from biosutilities.common.paths import make_dirs, safe_name
from biosutilities.common.executables import ms_pe, ms_pe_info
from biosutilities.common.patterns import PAT_MICROSOFT_MZ, PAT_MICROSOFT_PE, PAT_PHOENIX_TDK
from biosutilities.common.structs import CHAR, ctypes_struct, UINT32
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class PhoenixTdkHeader(ctypes.LittleEndianStructure):
    """ Phoenix TDK Header """

    _pack_ = 1
    _fields_ = [
        ('Tag',         CHAR * 8),      # 0x00
        ('Size',        UINT32),        # 0x08
        ('Count',       UINT32)         # 0x0C
        # 0x10
    ]

    def _get_tag(self) -> str:
        return self.Tag.decode(encoding='utf-8', errors='ignore').strip()

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Tag    :', self._get_tag()], padding=padding, new_line=False)
        printer(message=['Size   :', f'0x{self.Size:X}'], padding=padding, new_line=False)
        printer(message=['Entries:', self.Count], padding=padding, new_line=False)


class PhoenixTdkEntry(ctypes.LittleEndianStructure):
    """ Phoenix TDK Entry """

    _pack_ = 1
    _fields_ = [
        ('Name',        CHAR * 256),    # 0x000
        ('Offset',      UINT32),        # 0x100
        ('Size',        UINT32),        # 0x104
        ('Compressed',  UINT32),        # 0x108
        ('Reserved',    UINT32)         # 0x10C
        # 0x110
    ]

    COMP: Final[dict[int, str]] = {0: 'None', 1: 'LZMA'}

    def __init__(self, mz_base: int, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.mz_base: int = mz_base

    def get_name(self) -> str:
        """ Get TDK Entry decoded name """

        return self.Name.decode(encoding='utf-8', errors='replace').strip()

    def get_offset(self) -> int:
        """ Get TDK Entry absolute offset """

        return self.mz_base + self.Offset

    def get_compression(self) -> str:
        """ Get TDK Entry compression type """

        return self.COMP.get(self.Compressed, f'Unknown ({self.Compressed})')

    def struct_print(self, padding: int) -> None:
        """ Display structure information """

        printer(message=['Name       :', self.get_name()], padding=padding, new_line=False)
        printer(message=['Offset     :', f'0x{self.get_offset():X}'], padding=padding, new_line=False)
        printer(message=['Size       :', f'0x{self.Size:X}'], padding=padding, new_line=False)
        printer(message=['Compression:', self.get_compression()], padding=padding, new_line=False)
        printer(message=['Reserved   :', f'0x{self.Reserved:X}'], padding=padding, new_line=False)


class PhoenixTdkExtract(BIOSUtility):
    """ Phoenix TDK Packer Extractor """

    TITLE: str = 'Phoenix TDK Packer Extractor'

    TDK_HDR_LEN: Final[int] = ctypes.sizeof(PhoenixTdkHeader)
    TDK_MOD_LEN: Final[int] = ctypes.sizeof(PhoenixTdkEntry)

    TDK_DUMMY_LEN: Final[int] = 0x200

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input contains valid Phoenix TDK image """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        return bool(self._get_phoenix_tdk(in_buffer=input_buffer)[1] is not None)

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> int:
        """ Parse & Extract Phoenix Tools Development Kit (TDK) Packer """

        exit_code: int = 0

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        make_dirs(in_path=extract_path, delete=True)

        printer(message='Phoenix Tools Development Kit Packer', padding=padding)

        base_off, pack_off = self._get_phoenix_tdk(in_buffer=input_buffer)

        # Parse TDK Header structure
        tdk_hdr: Any = ctypes_struct(buffer=input_buffer, start_offset=pack_off, class_object=PhoenixTdkHeader)

        # Print TDK Header structure info
        printer(message='Phoenix TDK Header:\n', padding=padding + 4)

        tdk_hdr.struct_print(padding=padding + 8)

        # Check if reported TDK Header Size matches manual TDK Entry Count calculation
        if tdk_hdr.Size != self.TDK_HDR_LEN + self.TDK_DUMMY_LEN + tdk_hdr.Count * self.TDK_MOD_LEN:
            printer(message='Error: Phoenix TDK Header Size & Entry Count mismatch!\n', padding=padding + 8)

            exit_code = 1

        # Store TDK Entries offset after the placeholder data
        entries_off: int = pack_off + self.TDK_HDR_LEN + self.TDK_DUMMY_LEN

        # Parse and extract each TDK Header Entry
        for entry_index in range(tdk_hdr.Count):
            # Parse TDK Entry structure
            tdk_mod: Any = ctypes_struct(buffer=input_buffer, start_offset=entries_off + entry_index * self.TDK_MOD_LEN,
                                         class_object=PhoenixTdkEntry, param_list=[base_off])

            # Print TDK Entry structure info
            printer(message=f'Phoenix TDK Entry ({entry_index + 1}/{tdk_hdr.Count}):\n', padding=padding + 8)

            tdk_mod.struct_print(padding=padding + 12)

            # Get TDK Entry raw data Offset (TDK Base + Entry Offset)
            mod_off: int = tdk_mod.get_offset()

            # Check if TDK Entry raw data Offset is valid
            if mod_off >= len(input_buffer):
                printer(message='Error: Phoenix TDK Entry > Offset is out of bounds!\n', padding=padding + 12)

                exit_code = 2

            # Store TDK Entry raw data (relative to TDK Base, not TDK Header)
            mod_data: bytes = input_buffer[mod_off:mod_off + tdk_mod.Size]

            # Check if TDK Entry raw data is complete
            if len(mod_data) != tdk_mod.Size:
                printer(message='Error: Phoenix TDK Entry > Data is truncated!\n', padding=padding + 12)

                exit_code = 3

            # Check if TDK Entry Reserved is present
            if tdk_mod.Reserved:
                printer(message='Error: Phoenix TDK Entry > Reserved is not empty!\n', padding=padding + 12)

                exit_code = 4

            # Decompress TDK Entry raw data, when applicable (i.e. LZMA)
            if tdk_mod.get_compression() == 'LZMA':
                try:
                    mod_data = lzma.LZMADecompressor().decompress(data=mod_data)
                except Exception as error:  # pylint: disable=broad-except
                    printer(message=f'Error: Phoenix TDK Entry > LZMA decompression failed: {error}!\n',
                            padding=padding + 12)

                    exit_code = 5

            # Generate TDK Entry file name, avoid crash if Entry data is bad
            mod_name: str = tdk_mod.get_name() or f'Unknown_{entry_index + 1:02d}.bin'

            # Generate TDK Entry file data output path
            mod_file: str = os.path.join(extract_path, safe_name(mod_name))

            # Account for potential duplicate file names
            if os.path.isfile(path=mod_file):
                mod_file += f'_{entry_index + 1:02d}'

            # Save TDK Entry data to output file
            with open(file=mod_file, mode='wb') as out_file:
                out_file.write(mod_data)

        return exit_code

    @staticmethod
    def _get_tdk_base(in_buffer: bytes | bytearray, pack_off: int) -> int | None:
        """ Get Phoenix TDK Executable (MZ) Base Offset """

        # Initialize Phoenix TDK Base MZ Offset
        tdk_base_off: int | None = None

        # Scan input file for all Microsoft executable patterns (MZ) before TDK Header Offset
        mz_all: list[Match[bytes]] = [mz for mz in PAT_MICROSOFT_MZ.finditer(string=in_buffer) if mz.start() < pack_off]

        # Phoenix TDK Header structure is an index table for all TDK files
        # Each TDK file is referenced from the TDK Packer executable base
        # The TDK Header is always at the end of the TDK Packer executable
        # Thus, prefer the TDK Packer executable (MZ) closest to TDK Header
        # For speed, check MZ closest to (or at) 0x0 first (expected input)
        mz_ord: list[Match[bytes]] = [mz_all[0]] + list(reversed(mz_all[1:]))

        # Parse each detected MZ
        for mz_match in mz_ord:
            mz_off: int = mz_match.start()

            # MZ (DOS) > PE (NT) image Offset is found at offset 0x3C-0x40 relative to MZ base
            pe_off: int = mz_off + int.from_bytes(bytes=in_buffer[mz_off + 0x3C:mz_off + 0x40], byteorder='little')

            # Skip MZ (DOS) with bad PE (NT) image Offset
            if pe_off == mz_off or pe_off >= pack_off:
                continue

            # Check if potential MZ > PE image magic value is valid
            if PAT_MICROSOFT_PE.search(string=in_buffer[pe_off:pe_off + 0x4]):
                try:
                    # Parse detected MZ > PE > Image, quickly (fast_load)
                    pe_file: PE | None = ms_pe(in_file=in_buffer[mz_off:], silent=True)

                    if not pe_file:
                        raise RuntimeError('Failed to parse detected MZ > PE > Image!')

                    # Parse detected MZ > PE > Info
                    pe_info: dict = ms_pe_info(pe_file=pe_file, silent=True)

                    # Parse detected MZ > PE > Info > Product Name
                    pe_name: bytes = pe_info.get(b'ProductName', b'')
                except Exception as error:  # pylint: disable=broad-except
                    # Any error means no MZ > PE > Info > Product Name
                    logging.debug('Error: Invalid potential MZ > PE match at 0x%X: %s', pe_off, error)

                    pe_name = b''

                # Check for valid Phoenix TDK Packer PE > Product Name
                # Expected value is "TDK Packer (Extractor for Windows)"
                if pe_name.upper().startswith(b'TDK PACKER'):
                    # Set TDK Base Offset to valid TDK Packer MZ offset
                    tdk_base_off = mz_off

            # Stop parsing detected MZ once TDK Base Offset is found
            if tdk_base_off is not None:
                break
        else:
            # No TDK Base Offset could be found, assume 0x0
            tdk_base_off = 0x0

        return tdk_base_off

    def _get_phoenix_tdk(self, in_buffer: bytes | bytearray) -> tuple:
        """ Scan input buffer for valid Phoenix TDK image """

        # Scan input buffer for Phoenix TDK pattern
        tdk_match: Match[bytes] | None = PAT_PHOENIX_TDK.search(string=in_buffer)

        if not tdk_match:
            return None, None

        # Set Phoenix TDK Header ($PACK) Offset
        tdk_pack_off: int = tdk_match.start()

        # Get Phoenix TDK Executable (MZ) Base Offset
        tdk_base_off: int | None = self._get_tdk_base(in_buffer, tdk_pack_off)

        return tdk_base_off, tdk_pack_off


if __name__ == '__main__':
    PhoenixTdkExtract().run_utility()
