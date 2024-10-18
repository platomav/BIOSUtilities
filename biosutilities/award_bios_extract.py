#!/usr/bin/env python3 -B
# coding=utf-8

"""
Award BIOS Extract
Award BIOS Module Extractor
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import os

from biosutilities.common.compression import szip_decompress
from biosutilities.common.paths import clear_readonly, extract_folder, is_file, make_dirs, safe_name
from biosutilities.common.patterns import PAT_AWARD_LZH
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class AwardBiosExtract(BIOSUtility):
    """ Award BIOS Module Extractor """

    TITLE: str = 'Award BIOS Module Extractor'

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Award BIOS image """

        in_buffer: bytes = file_to_bytes(in_object=input_object)

        return bool(PAT_AWARD_LZH.search(in_buffer))

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool:
        """ Parse & Extract Award BIOS image """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        make_dirs(in_path=extract_path, delete=True)

        for lzh_match in PAT_AWARD_LZH.finditer(input_buffer):
            lzh_type: str = lzh_match.group(0).decode('utf-8')

            lzh_text: str = f'LZH-{lzh_type.strip("-").upper()}'

            lzh_bgn: int = lzh_match.start()

            mod_bgn: int = lzh_bgn - 0x2
            hdr_len: int = input_buffer[mod_bgn]
            mod_len: int = int.from_bytes(input_buffer[mod_bgn + 0x7:mod_bgn + 0xB], byteorder='little')
            mod_end: int = lzh_bgn + hdr_len + mod_len

            mod_bin: bytes = input_buffer[mod_bgn:mod_end]

            if len(mod_bin) != 0x2 + hdr_len + mod_len:
                printer(message=f'Error: Skipped incomplete LZH stream at 0x{mod_bgn:X}!',
                        padding=padding, new_line=True)

                continue

            if len(mod_bin) >= 0x16:
                tag_txt: str = safe_name(in_name=mod_bin[0x16:0x16 + mod_bin[0x15]].decode('utf-8', 'ignore').strip())
            else:
                tag_txt = f'{mod_bgn:X}_{mod_end:X}'

            printer(message=f'{lzh_text} > {tag_txt} [0x{mod_bgn:06X}-0x{mod_end:06X}]', padding=padding)

            mod_path: str = os.path.join(extract_path, tag_txt)

            lzh_path: str = f'{mod_path}.lzh'

            with open(lzh_path, 'wb') as lzh_file:
                lzh_file.write(mod_bin)  # Store LZH archive

            # 7-Zip returns critical exit code (i.e. 2) if LZH CRC is wrong, do not check result
            szip_decompress(in_path=lzh_path, out_path=extract_path, in_name=lzh_text,
                            padding=padding + 4)

            # Manually check if 7-Zip extracted LZH due to its CRC check issue
            if is_file(in_path=mod_path):
                clear_readonly(in_path=lzh_path)

                os.remove(lzh_path)  # Successful extraction, delete LZH archive

                # Extract any nested LZH archives
                if self.check_format(input_object=mod_path):
                    # Recursively extract nested Award BIOS modules
                    self.parse_format(input_object=mod_path, extract_path=extract_folder(mod_path),
                                      padding=padding + 8)

        return True


if __name__ == '__main__':
    AwardBiosExtract().run_utility()
