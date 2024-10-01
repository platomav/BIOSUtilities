#!/usr/bin/env python3 -B
# coding=utf-8

"""
Apple EFI IM4P
Apple EFI IM4P Splitter
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import os

from re import Match
from typing import Final

from biosutilities.common.paths import make_dirs, path_stem
from biosutilities.common.patterns import PAT_APPLE_IM4P, PAT_INTEL_IFD
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class AppleEfiIm4pSplit(BIOSUtility):
    """ Apple EFI IM4P Splitter """

    TITLE: str = 'Apple EFI IM4P Splitter'

    # Intel Flash Descriptor Component Sizes (4MB, 8MB, 16MB and 32MB)
    IFD_COMP_LEN: Final[dict[int, int]] = {3: 0x400000, 4: 0x800000, 5: 0x1000000, 6: 0x2000000}

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Apple EFI IM4P image """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        if PAT_APPLE_IM4P.search(string=input_buffer) and PAT_INTEL_IFD.search(string=input_buffer):
            return True

        return False

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> int:
        """ Parse & Split Apple EFI IM4P image """

        exit_codes: list[int] = []

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        make_dirs(in_path=extract_path, delete=True)

        # Detect IM4P EFI pattern
        im4p_match: Match[bytes] | None = PAT_APPLE_IM4P.search(string=input_buffer)

        if not im4p_match:
            return 1

        # After IM4P mefi (0x15), multi EFI payloads have _MEFIBIN (0x100) but is difficult to RE w/o varying samples.
        # However, _MEFIBIN is not required for splitting SPI images due to Intel Flash Descriptor Components Density.

        # IM4P mefi payload start offset
        mefi_data_bgn: int = im4p_match.start() + input_buffer[im4p_match.start() - 0x1]

        # IM4P mefi payload size
        mefi_data_len: int = int.from_bytes(bytes=input_buffer[im4p_match.end() + 0x5:im4p_match.end() + 0x9],
                                            byteorder='big')

        # Check if mefi is followed by _MEFIBIN
        mefibin_exist: bool = input_buffer[mefi_data_bgn:mefi_data_bgn + 0x8] == b'_MEFIBIN'

        # Actual multi EFI payloads start after _MEFIBIN
        efi_data_bgn: int = mefi_data_bgn + 0x100 if mefibin_exist else mefi_data_bgn

        # Actual multi EFI payloads size without _MEFIBIN
        efi_data_len: int = mefi_data_len - 0x100 if mefibin_exist else mefi_data_len

        # Adjust input file buffer to actual multi EFI payloads data
        input_buffer = input_buffer[efi_data_bgn:efi_data_bgn + efi_data_len]

        # Parse Intel Flash Descriptor pattern matches
        for ifd in PAT_INTEL_IFD.finditer(string=input_buffer):
            # Component Base Address from FD start (ICH8-ICH10 = 1, IBX = 2, CPT+ = 3)
            ifd_flmap0_fcba: int = input_buffer[ifd.start() + 0x4] * 0x10

            # I/O Controller Hub (ICH)
            if ifd_flmap0_fcba == 0x10:
                # At ICH, Flash Descriptor starts at 0x0
                ifd_bgn_subtruct: int = 0x0

                # 0xBC for [0xAC] + 0xFF * 16 sanity check
                ifd_end_subtruct: int = 0xBC

            # Platform Controller Hub (PCH)
            else:
                # At PCH, Flash Descriptor starts at 0x10
                ifd_bgn_subtruct = 0x10

                # 0xBC for [0xAC] + 0xFF * 16 sanity check
                ifd_end_subtruct = 0xBC

            # Actual Flash Descriptor Start Offset
            ifd_match_start: int = ifd.start() - ifd_bgn_subtruct

            # Actual Flash Descriptor End Offset
            ifd_match_end: int = ifd.end() - ifd_end_subtruct

            # Calculate Intel Flash Descriptor Flash Component Total Size

            # Component Count (00 = 1, 01 = 2)
            ifd_flmap0_nc: int = ((int.from_bytes(bytes=input_buffer[ifd_match_end:ifd_match_end + 0x4],
                                                  byteorder='little') >> 8) & 3) + 1

            # PCH/ICH Strap Length (ME 2-8 & TXE 0-2 & SPS 1-2 <= 0x12, ME 9+ & TXE 3+ & SPS 3+ >= 0x13)
            ifd_flmap1_isl: int = input_buffer[ifd_match_end + 0x7]

            # Component Density Byte (ME 2-8 & TXE 0-2 & SPS 1-2 = 0:5, ME 9+ & TXE 3+ & SPS 3+ = 0:7)
            ifd_comp_den: int = input_buffer[ifd_match_start + ifd_flmap0_fcba]

            # Component 1 Density Bits (ME 2-8 & TXE 0-2 & SPS 1-2 = 3, ME 9+ & TXE 3+ & SPS 3+ = 4)
            ifd_comp_1_bitwise: int = 0xF if ifd_flmap1_isl >= 0x13 else 0x7

            # Component 2 Density Bits (ME 2-8 & TXE 0-2 & SPS 1-2 = 3, ME 9+ & TXE 3+ & SPS 3+ = 4)
            ifd_comp_2_bitwise: int = 0x4 if ifd_flmap1_isl >= 0x13 else 0x3

            # Component 1 Density (FCBA > C0DEN)
            ifd_comp_all_size: int = self.IFD_COMP_LEN[ifd_comp_den & ifd_comp_1_bitwise]

            # Component 2 Density (FCBA > C1DEN)
            if ifd_flmap0_nc == 2:
                ifd_comp_all_size += self.IFD_COMP_LEN[ifd_comp_den >> ifd_comp_2_bitwise]

            ifd_data_bgn: int = ifd_match_start
            ifd_data_end: int = ifd_data_bgn + ifd_comp_all_size

            ifd_data_txt: str = f'0x{ifd_data_bgn:07X}-0x{ifd_data_end:07X}'

            output_data: bytes = input_buffer[ifd_data_bgn:ifd_data_end]

            output_size: int = len(output_data)

            output_name: str = path_stem(in_path=input_object) if isinstance(input_object, str) else 'Part'

            output_path: str = os.path.join(extract_path, f'{output_name}_[{ifd_data_txt}].fd')

            with open(file=output_path, mode='wb') as output_image:
                output_image.write(output_data)

            printer(message=f'Split Apple EFI image at {ifd_data_txt}!', padding=padding)

            if output_size != ifd_comp_all_size:
                printer(message=f'Error: Bad image size 0x{output_size:07X}, expected 0x{ifd_comp_all_size:07X}!',
                        padding=padding + 4)

                exit_codes.append(1)

        return sum(exit_codes)


if __name__ == '__main__':
    AppleEfiIm4pSplit().run_utility()
