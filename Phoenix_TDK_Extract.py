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

from common.path_ops import make_dirs, safe_name
from common.pe_ops import get_pe_file, get_pe_info
from common.patterns import PAT_MICROSOFT_MZ, PAT_MICROSOFT_PE, PAT_PHOENIX_TDK
from common.struct_ops import Char, get_struct, UInt32
from common.system import printer
from common.templates import BIOSUtility
from common.text_ops import file_to_bytes

TITLE = 'Phoenix TDK Packer Extractor v3.0'


class PhoenixTdkHeader(ctypes.LittleEndianStructure):
    """ Phoenix TDK Header """

    _pack_ = 1
    _fields_ = [
        ('Tag', Char * 8),  # 0x00
        ('Size', UInt32),  # 0x08
        ('Count', UInt32),  # 0x0C
        # 0x10
    ]

    def _get_tag(self):
        return self.Tag.decode('utf-8', 'ignore').strip()

    def struct_print(self, padd):
        """ Display structure information """

        printer(['Tag    :', self._get_tag()], padd, False)
        printer(['Size   :', f'0x{self.Size:X}'], padd, False)
        printer(['Entries:', self.Count], padd, False)


class PhoenixTdkEntry(ctypes.LittleEndianStructure):
    """ Phoenix TDK Entry """

    _pack_ = 1
    _fields_ = [
        ('Name', Char * 256),  # 0x000
        ('Offset', UInt32),  # 0x100
        ('Size', UInt32),  # 0x104
        ('Compressed', UInt32),  # 0x108
        ('Reserved', UInt32),  # 0x10C
        # 0x110
    ]

    COMP = {0: 'None', 1: 'LZMA'}

    def __init__(self, mz_base, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.mz_base = mz_base

    def get_name(self):
        """ Get TDK Entry decoded name """

        return self.Name.decode('utf-8', 'replace').strip()

    def get_offset(self):
        """ Get TDK Entry absolute offset """

        return self.mz_base + self.Offset

    def get_compression(self):
        """ Get TDK Entry compression type """

        return self.COMP.get(self.Compressed, f'Unknown ({self.Compressed})')

    def struct_print(self, padd):
        """ Display structure information """

        printer(['Name       :', self.get_name()], padd, False)
        printer(['Offset     :', f'0x{self.get_offset():X}'], padd, False)
        printer(['Size       :', f'0x{self.Size:X}'], padd, False)
        printer(['Compression:', self.get_compression()], padd, False)
        printer(['Reserved   :', f'0x{self.Reserved:X}'], padd, False)


def get_tdk_base(in_buffer, pack_off):
    """ Get Phoenix TDK Executable (MZ) Base Offset """

    tdk_base_off = None  # Initialize Phoenix TDK Base MZ Offset

    # Scan input file for all Microsoft executable patterns (MZ) before TDK Header Offset
    mz_all = [mz for mz in PAT_MICROSOFT_MZ.finditer(in_buffer) if mz.start() < pack_off]

    # Phoenix TDK Header structure is an index table for all TDK files
    # Each TDK file is referenced from the TDK Packer executable base
    # The TDK Header is always at the end of the TDK Packer executable
    # Thus, prefer the TDK Packer executable (MZ) closest to TDK Header
    # For speed, check MZ closest to (or at) 0x0 first (expected input)
    mz_ord = [mz_all[0]] + list(reversed(mz_all[1:]))

    # Parse each detected MZ
    for mz_match in mz_ord:
        mz_off = mz_match.start()

        # MZ (DOS) > PE (NT) image Offset is found at offset 0x3C-0x40 relative to MZ base
        pe_off = mz_off + int.from_bytes(in_buffer[mz_off + 0x3C:mz_off + 0x40], 'little')

        # Skip MZ (DOS) with bad PE (NT) image Offset
        if pe_off == mz_off or pe_off >= pack_off:
            continue

        # Check if potential MZ > PE image magic value is valid
        if PAT_MICROSOFT_PE.search(in_buffer[pe_off:pe_off + 0x4]):
            try:
                # Parse detected MZ > PE > Image, quickly (fast_load)
                pe_file = get_pe_file(in_buffer[mz_off:], silent=True)

                # Parse detected MZ > PE > Info
                pe_info = get_pe_info(pe_file, silent=True)

                # Parse detected MZ > PE > Info > Product Name
                pe_name = pe_info.get(b'ProductName', b'')
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


def get_phoenix_tdk(in_buffer):
    """ Scan input buffer for valid Phoenix TDK image """

    # Scan input buffer for Phoenix TDK pattern
    tdk_match = PAT_PHOENIX_TDK.search(in_buffer)

    if not tdk_match:
        return None, None

    # Set Phoenix TDK Header ($PACK) Offset
    tdk_pack_off = tdk_match.start()

    # Get Phoenix TDK Executable (MZ) Base Offset
    tdk_base_off = get_tdk_base(in_buffer, tdk_pack_off)

    return tdk_base_off, tdk_pack_off


def is_phoenix_tdk(in_file):
    """ Check if input contains valid Phoenix TDK image """

    buffer = file_to_bytes(in_file)

    return bool(get_phoenix_tdk(buffer)[1] is not None)


def phoenix_tdk_extract(input_file, extract_path, padding=0):
    """ Parse & Extract Phoenix Tools Development Kit (TDK) Packer """

    exit_code = 0

    input_buffer = file_to_bytes(input_file)

    make_dirs(extract_path, delete=True)

    printer('Phoenix Tools Development Kit Packer', padding)

    base_off, pack_off = get_phoenix_tdk(input_buffer)

    # Parse TDK Header structure
    tdk_hdr = get_struct(input_buffer, pack_off, PhoenixTdkHeader)

    # Print TDK Header structure info
    printer('Phoenix TDK Header:\n', padding + 4)

    tdk_hdr.struct_print(padding + 8)

    # Check if reported TDK Header Size matches manual TDK Entry Count calculation
    if tdk_hdr.Size != TDK_HDR_LEN + TDK_DUMMY_LEN + tdk_hdr.Count * TDK_MOD_LEN:
        printer('Error: Phoenix TDK Header Size & Entry Count mismatch!\n', padding + 8, pause=True)

        exit_code = 1

    # Store TDK Entries offset after the placeholder data
    entries_off = pack_off + TDK_HDR_LEN + TDK_DUMMY_LEN

    # Parse and extract each TDK Header Entry
    for entry_index in range(tdk_hdr.Count):
        # Parse TDK Entry structure
        tdk_mod = get_struct(input_buffer, entries_off + entry_index * TDK_MOD_LEN, PhoenixTdkEntry, [base_off])

        # Print TDK Entry structure info
        printer(f'Phoenix TDK Entry ({entry_index + 1}/{tdk_hdr.Count}):\n', padding + 8)

        tdk_mod.struct_print(padding + 12)

        # Get TDK Entry raw data Offset (TDK Base + Entry Offset)
        mod_off = tdk_mod.get_offset()

        # Check if TDK Entry raw data Offset is valid
        if mod_off >= len(input_buffer):
            printer('Error: Phoenix TDK Entry > Offset is out of bounds!\n', padding + 12, pause=True)

            exit_code = 2

        # Store TDK Entry raw data (relative to TDK Base, not TDK Header)
        mod_data = input_buffer[mod_off:mod_off + tdk_mod.Size]

        # Check if TDK Entry raw data is complete
        if len(mod_data) != tdk_mod.Size:
            printer('Error: Phoenix TDK Entry > Data is truncated!\n', padding + 12, pause=True)

            exit_code = 3

        # Check if TDK Entry Reserved is present
        if tdk_mod.Reserved:
            printer('Error: Phoenix TDK Entry > Reserved is not empty!\n', padding + 12, pause=True)

            exit_code = 4

        # Decompress TDK Entry raw data, when applicable (i.e. LZMA)
        if tdk_mod.get_compression() == 'LZMA':
            try:
                mod_data = lzma.LZMADecompressor().decompress(mod_data)
            except Exception as error:  # pylint: disable=broad-except
                printer(f'Error: Phoenix TDK Entry > LZMA decompression failed: {error}!\n', padding + 12, pause=True)

                exit_code = 5

        # Generate TDK Entry file name, avoid crash if Entry data is bad
        mod_name = tdk_mod.get_name() or f'Unknown_{entry_index + 1:02d}.bin'

        # Generate TDK Entry file data output path
        mod_file = os.path.join(extract_path, safe_name(mod_name))

        # Account for potential duplicate file names
        if os.path.isfile(mod_file):
            mod_file += f'_{entry_index + 1:02d}'

        # Save TDK Entry data to output file
        with open(mod_file, 'wb') as out_file:
            out_file.write(mod_data)

    return exit_code


# Get ctypes Structure Sizes
TDK_HDR_LEN = ctypes.sizeof(PhoenixTdkHeader)
TDK_MOD_LEN = ctypes.sizeof(PhoenixTdkEntry)

# Set placeholder TDK Entries Size
TDK_DUMMY_LEN = 0x200

if __name__ == '__main__':
    BIOSUtility(title=TITLE, check=is_phoenix_tdk, main=phoenix_tdk_extract).run_utility()
