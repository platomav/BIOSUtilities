#!/usr/bin/env python3 -B
# coding=utf-8

"""
Fujitsu SFX Extractor
Fujitsu SFX BIOS Extractor
Copyright (C) 2019-2024 Plato Mavropoulos
"""

import os
import re

from biosutilities.common.compression import is_szip_supported, szip_decompress
from biosutilities.common.paths import make_dirs
from biosutilities.common.patterns import PAT_FUJITSU_SFX
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class FujitsuSfxExtract(BIOSUtility):
    """ Fujitsu SFX BIOS Extractor """

    TITLE: str = 'Fujitsu SFX BIOS Extractor'

    def check_format(self) -> bool:
        """ Check if input is Fujitsu SFX image """

        input_buffer: bytes = file_to_bytes(in_object=self.input_object)

        return bool(PAT_FUJITSU_SFX.search(input_buffer))

    def parse_format(self) -> bool:
        """ Parse & Extract Fujitsu SFX image """

        input_buffer: bytes = file_to_bytes(in_object=self.input_object)

        # Microsoft CAB Header XOR 0xFF
        match_cab: re.Match[bytes] | None = PAT_FUJITSU_SFX.search(input_buffer)

        if not match_cab:
            return False

        printer(message='Detected obfuscated CAB archive!', padding=self.padding)

        # Microsoft CAB Header XOR 0xFF starts after "FjSfxBinay" signature
        cab_start: int = match_cab.start() + 0xA

        # Get LE XOR-ed CAB size
        cab_size: int = int.from_bytes(input_buffer[cab_start + 0x8:cab_start + 0xC], byteorder='little')

        # Create CAB size XOR value
        xor_size: int = int.from_bytes(b'\xFF' * 0x4, byteorder='little')

        # Perform XOR 0xFF and get actual CAB size
        cab_size ^= xor_size

        printer(message='Removing obfuscation...', padding=self.padding + 4)

        # Get BE XOR-ed CAB data
        cab_data: int = int.from_bytes(input_buffer[cab_start:cab_start + cab_size], byteorder='big')

        # Create CAB data XOR value
        xor_data: int = int.from_bytes(b'\xFF' * cab_size, byteorder='big')

        # Perform XOR 0xFF and get actual CAB data
        raw_data: bytes = (cab_data ^ xor_data).to_bytes(cab_size, 'big')

        printer(message='Extracting archive...', padding=self.padding + 4)

        make_dirs(in_path=self.extract_path, delete=True)

        cab_path: str = os.path.join(self.extract_path, 'FjSfxBinay.cab')

        # Create temporary CAB archive
        with open(cab_path, 'wb') as cab_file_object:
            cab_file_object.write(raw_data)

        if is_szip_supported(in_path=cab_path, padding=self.padding + 8, silent=False):
            if szip_decompress(in_path=cab_path, out_path=self.extract_path, in_name='FjSfxBinay CAB',
                               padding=self.padding + 8, check=True):
                os.remove(cab_path)
            else:
                return False
        else:
            return False

        return True
