#!/usr/bin/env python3 -B
# coding=utf-8

"""
Apple PBZX Extract
Apple EFI PBZX Extractor
Copyright (C) 2021-2024 Plato Mavropoulos
"""

import ctypes
import logging
import lzma
import os

from typing import Any, Final

from biosutilities.common.compression import is_szip_supported, szip_decompress
from biosutilities.common.paths import make_dirs, path_stem
from biosutilities.common.patterns import PAT_APPLE_PBZX
from biosutilities.common.structs import ctypes_struct, UINT32
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class PbzxChunk(ctypes.BigEndianStructure):
    """ PBZX Chunk Header """

    _pack_ = 1
    _fields_ = [
        ('Reserved0',       UINT32),        # 0x00
        ('InitSize',        UINT32),        # 0x04
        ('Reserved1',       UINT32),        # 0x08
        ('CompSize',        UINT32)         # 0x0C
        # 0x10
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Reserved 0     :', f'0x{self.Reserved0:X}'], padding=padding, new_line=False)
        printer(message=['Initial Size   :', f'0x{self.InitSize:X}'], padding=padding, new_line=False)
        printer(message=['Reserved 1     :', f'0x{self.Reserved1:X}'], padding=padding, new_line=False)
        printer(message=['Compressed Size:', f'0x{self.CompSize:X}'], padding=padding, new_line=False)


class AppleEfiPbzxExtract(BIOSUtility):
    """ Apple EFI PBZX Extractor """

    TITLE: str = 'Apple EFI PBZX Extractor'

    PBZX_CHUNK_HDR_LEN: Final[int] = ctypes.sizeof(PbzxChunk)

    def check_format(self) -> bool:
        """ Check if input is Apple PBZX image """

        input_buffer: bytes = file_to_bytes(in_object=self.input_object)

        return bool(PAT_APPLE_PBZX.search(input_buffer, 0, 4))

    def parse_format(self) -> bool:
        """ Parse & Extract Apple PBZX image """

        input_buffer: bytes = file_to_bytes(in_object=self.input_object)

        make_dirs(in_path=self.extract_path, delete=True)

        cpio_bin: bytes = b''  # Initialize PBZX > CPIO Buffer

        cpio_len: int = 0x0  # Initialize PBZX > CPIO Length

        chunk_off: int = 0xC  # First PBZX Chunk starts at 0xC

        while chunk_off < len(input_buffer):
            chunk_hdr: Any = ctypes_struct(buffer=input_buffer, start_offset=chunk_off, class_object=PbzxChunk)

            printer(message=f'PBZX Chunk at 0x{chunk_off:08X}\n', padding=self.padding)

            chunk_hdr.struct_print(padding=self.padding + 4)

            # PBZX Chunk data starts after its Header
            comp_bgn: int = chunk_off + self.PBZX_CHUNK_HDR_LEN

            # To avoid a potential infinite loop, double-check Compressed Size
            comp_end: int = comp_bgn + max(chunk_hdr.CompSize, self.PBZX_CHUNK_HDR_LEN)

            comp_bin: bytes = input_buffer[comp_bgn:comp_end]

            try:
                # Attempt XZ decompression, if applicable to Chunk data
                cpio_bin += lzma.LZMADecompressor().decompress(comp_bin)

                printer(message='Successful LZMA decompression!', padding=self.padding + 8)
            except Exception as error:  # pylint: disable=broad-except
                logging.debug('Error: Failed to LZMA decompress PBZX Chunk 0x%X: %s', chunk_off, error)

                # Otherwise, Chunk data is not compressed
                cpio_bin += comp_bin

            # Final CPIO size should match the sum of all Chunks > Initial Size
            cpio_len += chunk_hdr.InitSize

            # Next Chunk starts at the end of current Chunk's data
            chunk_off = comp_end

        # Check that CPIO size is valid based on all Chunks > Initial Size
        if cpio_len != len(cpio_bin):
            printer(message='Error: Unexpected CPIO archive size!', padding=self.padding)

            return False

        cpio_name: str = path_stem(in_path=self.input_object) if isinstance(self.input_object, str) else 'Payload'

        cpio_path: str = os.path.join(self.extract_path, f'{cpio_name}.cpio')

        with open(cpio_path, 'wb') as cpio_object:
            cpio_object.write(cpio_bin)

        # Decompress PBZX > CPIO archive with 7-Zip
        if is_szip_supported(in_path=cpio_path, padding=self.padding, args=['-tCPIO'], silent=False):
            if szip_decompress(in_path=cpio_path, out_path=self.extract_path, in_name='CPIO',
                               padding=self.padding, args=['-tCPIO']):
                os.remove(cpio_path)  # Successful extraction, delete PBZX > CPIO archive
            else:
                return False
        else:
            return False

        return True
