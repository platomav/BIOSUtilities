#!/usr/bin/env python3 -B
# coding=utf-8

"""
Award BIOS Extract
Award BIOS Module Extractor
Copyright (C) 2018-2025 Plato Mavropoulos
"""

import os

from biosutilities.common.compression import szip_decompress
from biosutilities.common.paths import (clear_readonly, delete_file, extract_folder, is_file_read,
                                        make_dirs, safe_name)
from biosutilities.common.patterns import PAT_AWARD_LZH
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility


class AwardBiosExtract(BIOSUtility):
    """ Award BIOS Module Extractor """

    TITLE: str = 'Award BIOS Module Extractor'

    def check_format(self) -> bool:
        """ Check if input is Award BIOS image """

        return bool(PAT_AWARD_LZH.search(self.input_buffer))

    def parse_format(self) -> bool:
        """ Parse & Extract Award BIOS image """

        make_dirs(in_path=self.extract_path)

        for lzh_match in PAT_AWARD_LZH.finditer(self.input_buffer):
            lzh_type: str = lzh_match.group(0).decode('utf-8')

            lzh_text: str = f'LZH-{lzh_type.strip("-").upper()}'

            lzh_bgn: int = lzh_match.start()

            mod_bgn: int = lzh_bgn - 0x2
            hdr_len: int = self.input_buffer[mod_bgn]
            mod_len: int = int.from_bytes(self.input_buffer[mod_bgn + 0x7:mod_bgn + 0xB], byteorder='little')
            mod_end: int = lzh_bgn + hdr_len + mod_len

            mod_bin: bytes = self.input_buffer[mod_bgn:mod_end]

            if len(mod_bin) != 0x2 + hdr_len + mod_len:
                printer(message=f'Error: Skipped incomplete LZH stream at 0x{mod_bgn:X}!',
                        padding=self.padding, new_line=True)

                continue

            if len(mod_bin) > 0x16:
                tag_txt: str = safe_name(in_name=mod_bin[0x16:0x16 + mod_bin[0x15]].decode('utf-8', 'ignore').strip())
            else:
                tag_txt = f'{mod_bgn:X}_{mod_end:X}'

            printer(message=f'{lzh_text} > {tag_txt} [0x{mod_bgn:06X}-0x{mod_end:06X}]', padding=self.padding)

            mod_path: str = os.path.join(self.extract_path, tag_txt)

            lzh_path: str = f'{mod_path}.lzh'

            with open(lzh_path, 'wb') as lzh_file:
                lzh_file.write(mod_bin)  # Store LZH archive

            # 7-Zip returns critical exit code (i.e. 2) if LZH CRC is wrong, do not check result
            szip_decompress(in_path=lzh_path, out_path=self.extract_path, in_name=lzh_text,
                            padding=self.padding + 4)

            # Manually check if 7-Zip extracted LZH due to its CRC check issue
            if is_file_read(in_path=mod_path):
                clear_readonly(in_path=lzh_path)

                delete_file(in_path=lzh_path)  # Successful extraction, delete LZH archive

                award_bios_extract: AwardBiosExtract = AwardBiosExtract(
                    input_object=mod_path, extract_path=extract_folder(mod_path), padding=self.padding + 8)

                # Extract any nested LZH archives
                if award_bios_extract.check_format():
                    award_bios_extract.parse_format()

        return True
