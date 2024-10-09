#!/usr/bin/env python3 -B
# coding=utf-8

"""
Panasonic BIOS Extract
Panasonic BIOS Package Extractor
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import io
import logging
import os
import re

from typing import Final

import pefile

# noinspection PyPackageRequirements
from dissect.util.compression import lznt1

from biosutilities.common.compression import is_szip_supported, szip_decompress
from biosutilities.common.paths import is_access, is_file, path_files, make_dirs, path_stem, safe_name
from biosutilities.common.executables import ms_pe_desc, ms_pe, is_ms_pe, ms_pe_info_show
from biosutilities.common.patterns import PAT_MICROSOFT_CAB
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes

from biosutilities.ami_pfat_extract import AmiPfatExtract


class PanasonicBiosExtract(BIOSUtility):
    """ Panasonic BIOS Package Extractor """

    TITLE: str = 'Panasonic BIOS Package Extractor'

    PAN_PE_DESC_UNP: Final[str] = 'UNPACK UTILITY'

    PAN_PE_DESC_UPD: Final[str] = 'BIOS UPDATE'

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Panasonic BIOS Package PE """

        pe_file: pefile.PE | None = ms_pe(in_file=input_object, silent=True)

        if not pe_file:
            return False

        if ms_pe_desc(pe_file=pe_file, silent=True).decode(encoding='utf-8', errors='ignore').upper() not in (
                self.PAN_PE_DESC_UNP, self.PAN_PE_DESC_UPD):
            return False

        return True

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool:
        """ Parse & Extract Panasonic BIOS Package PE """

        upd_pe_file: pefile.PE = ms_pe(in_file=input_object, padding=padding)  # type: ignore

        upd_pe_name: str = self._panasonic_pkg_name(input_object=input_object)

        printer(message=f'Panasonic BIOS Package > PE ({upd_pe_name})\n'.replace(' ()', ''), padding=padding)

        ms_pe_info_show(pe_file=upd_pe_file, padding=padding + 4)

        make_dirs(in_path=extract_path, delete=True)

        upd_pe_path: str = self._panasonic_cab_extract(input_object=input_object,
                                                       extract_path=extract_path, padding=padding + 8)

        upd_padding: int = padding

        if upd_pe_path:
            upd_padding = padding + 16

            upd_pe_name = self._panasonic_pkg_name(input_object=upd_pe_path)

            printer(message=f'Panasonic BIOS Update > PE ({upd_pe_name})\n'.replace(' ()', ''), padding=upd_padding)

            upd_pe_file = ms_pe(in_file=upd_pe_path, padding=upd_padding)  # type: ignore

            ms_pe_info_show(pe_file=upd_pe_file, padding=upd_padding + 4)

            os.remove(path=upd_pe_path)

        is_upd_extracted: bool = self._panasonic_res_extract(pe_file=upd_pe_file, extract_path=extract_path,
                                                             pe_name=upd_pe_name, padding=upd_padding + 8)

        if not is_upd_extracted:
            is_upd_extracted = self._panasonic_img_extract(pe_file=upd_pe_file, extract_path=extract_path,
                                                           pe_name=upd_pe_name, padding=upd_padding + 8)

        return is_upd_extracted

    @staticmethod
    def _panasonic_pkg_name(input_object: str | bytes | bytearray) -> str:
        """ Get Panasonic BIOS Package file name, when applicable """

        if isinstance(input_object, str) and is_file(in_path=input_object):
            return safe_name(in_name=path_stem(in_path=input_object))

        return ''

    def _panasonic_cab_extract(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> str:
        """ Search and Extract Panasonic BIOS Package PE CAB archive """

        input_data: bytes = file_to_bytes(in_object=input_object)

        cab_match: re.Match[bytes] | None = PAT_MICROSOFT_CAB.search(string=input_data)

        if cab_match:
            cab_bgn: int = cab_match.start()

            cab_end: int = cab_bgn + int.from_bytes(bytes=input_data[cab_bgn + 0x8:cab_bgn + 0xC], byteorder='little')

            cab_tag: str = f'[0x{cab_bgn:06X}-0x{cab_end:06X}]'

            cab_path: str = os.path.join(extract_path, f'CAB_{cab_tag}.cab')

            with open(file=cab_path, mode='wb') as cab_file_object:
                cab_file_object.write(input_data[cab_bgn:cab_end])

            if is_szip_supported(in_path=cab_path, padding=padding, silent=False):
                printer(message=f'Panasonic BIOS Package > PE > CAB {cab_tag}', padding=padding)

                if szip_decompress(in_path=cab_path, out_path=extract_path, in_name='CAB',
                                   padding=padding + 4, check=True):
                    os.remove(path=cab_path)  # Successful extraction, delete CAB archive

                    for extracted_file_path in path_files(in_path=extract_path):
                        if is_file(in_path=extracted_file_path) and is_access(in_path=extracted_file_path):
                            extracted_pe_file: pefile.PE | None = ms_pe(
                                in_file=extracted_file_path, padding=padding, silent=True)

                            if extracted_pe_file:
                                extracted_pe_desc: bytes = ms_pe_desc(pe_file=extracted_pe_file, silent=True)

                                if extracted_pe_desc.decode(encoding='utf-8', errors='ignore'
                                                            ).upper() == self.PAN_PE_DESC_UPD:
                                    return extracted_file_path

        return ''

    @staticmethod
    def _panasonic_res_extract(pe_file: pefile.PE, extract_path: str, pe_name: str = '', padding: int = 0) -> bool:
        """ Extract & Decompress Panasonic BIOS Update PE RCDATA (LZNT1) """

        is_rcdata: bool = False

        # When fast_load is used, IMAGE_DIRECTORY_ENTRY_RESOURCE must be parsed prior to RCDATA Directories
        pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        # noinspection PyUnresolvedReferences
        for entry in pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
            # Parse all Resource Data Directories > RCDATA (ID = 10)
            if entry.struct.name == 'IMAGE_RESOURCE_DIRECTORY_ENTRY' and entry.struct.Id == 0xA:
                is_rcdata = True

                for resource in entry.directory.entries:
                    res_bgn: int = resource.directory.entries[0].data.struct.OffsetToData
                    res_len: int = resource.directory.entries[0].data.struct.Size
                    res_end: int = res_bgn + res_len

                    res_bin: bytes = pe_file.get_data(res_bgn, res_len)

                    res_tag: str = f'{pe_name} [0x{res_bgn:06X}-0x{res_end:06X}]'.strip()

                    res_out: str = os.path.join(extract_path, f'{res_tag}')

                    printer(message=res_tag, padding=padding)

                    try:
                        res_raw: bytes = lznt1.decompress(src=res_bin[0x8:])

                        if len(res_raw) != int.from_bytes(bytes=res_bin[0x4:0x8], byteorder='little'):
                            raise ValueError('LZNT1_DECOMPRESS_BAD_SIZE')

                        printer(message='Successful LZNT1 decompression via Dissect!', padding=padding + 4)
                    except Exception as error:  # pylint: disable=broad-except
                        logging.debug('Error: LZNT1 decompression of %s failed: %s', res_tag, error)

                        res_raw = res_bin

                        printer(message='Successful PE Resource extraction!', padding=padding + 4)

                    ami_pfat_extract: AmiPfatExtract = AmiPfatExtract()

                    # Detect & Unpack AMI BIOS Guard (PFAT) BIOS image
                    if ami_pfat_extract.check_format(input_object=res_raw):
                        pfat_dir: str = os.path.join(extract_path, res_tag)

                        ami_pfat_extract.parse_format(input_object=res_raw, extract_path=pfat_dir,
                                                      padding=padding + 8)
                    else:
                        if is_ms_pe(in_file=res_raw):
                            res_ext: str = 'exe'
                        elif res_raw.startswith(b'[') and res_raw.endswith((b'\x0D\x0A', b'\x0A')):
                            res_ext = 'txt'
                        else:
                            res_ext = 'bin'

                        if res_ext == 'txt':
                            printer(message=None, new_line=False)

                            for line in io.BytesIO(res_raw).readlines():
                                line_text: str = line.decode(encoding='utf-8', errors='ignore').rstrip()

                                printer(message=line_text, padding=padding + 8, new_line=False)

                        with open(file=f'{res_out}.{res_ext}', mode='wb') as out_file_object:
                            out_file_object.write(res_raw)

        return is_rcdata

    @staticmethod
    def _panasonic_img_extract(pe_file: pefile.PE, extract_path: str, pe_name: str = '',
                               padding: int = 0) -> bool:
        """ Extract Panasonic BIOS Update PE Data when RCDATA is not available """

        pe_data: bytes = bytes(pe_file.__data__)

        sec_bgn: int = pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[
            'IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

        img_bgn: int = (pe_file.OPTIONAL_HEADER.BaseOfData +  # type: ignore
                        pe_file.OPTIONAL_HEADER.SizeOfInitializedData)

        img_end: int = sec_bgn or len(pe_data)

        img_bin: bytes = pe_data[img_bgn:img_end]

        img_tag: str = f'{pe_name} [0x{img_bgn:X}-0x{img_end:X}]'.strip()

        img_out: str = os.path.join(extract_path, f'{img_tag}.bin')

        printer(message=img_tag, padding=padding)

        with open(file=img_out, mode='wb') as out_img_object:
            out_img_object.write(img_bin)

        printer(message='Successful PE Data extraction!', padding=padding + 4)

        return bool(img_bin)


if __name__ == '__main__':
    PanasonicBiosExtract().run_utility()
