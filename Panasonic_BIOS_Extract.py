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

from re import Match

import pefile

from dissect.util.compression import lznt1

from common.comp_szip import is_szip_supported, szip_decompress
from common.path_ops import get_path_files, make_dirs, path_stem, safe_name
from common.pe_ops import get_pe_desc, get_pe_file, is_pe_file, show_pe_info
from common.patterns import PAT_MICROSOFT_CAB
from common.system import printer
from common.templates import BIOSUtility
from common.text_ops import file_to_bytes

from AMI_PFAT_Extract import is_ami_pfat, parse_pfat_file

TITLE = 'Panasonic BIOS Package Extractor v4.0'


def is_panasonic_pkg(input_object: str | bytes | bytearray) -> bool:
    """ Check if input is Panasonic BIOS Package PE """

    pe_file: pefile.PE | None = get_pe_file(input_object, silent=True)

    if not pe_file:
        return False

    if get_pe_desc(pe_file, silent=True).decode('utf-8', 'ignore').upper() not in (PAN_PE_DESC_UNP, PAN_PE_DESC_UPD):
        return False

    return True


def panasonic_pkg_name(input_object: str | bytes | bytearray) -> str:
    """ Get Panasonic BIOS Package file name, when applicable """

    if isinstance(input_object, str) and os.path.isfile(input_object):
        return safe_name(path_stem(input_object))

    return ''


def panasonic_cab_extract(input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> str:
    """ Search and Extract Panasonic BIOS Package PE CAB archive """

    input_data: bytes = file_to_bytes(input_object)

    cab_match: Match[bytes] | None = PAT_MICROSOFT_CAB.search(input_data)

    if cab_match:
        cab_bgn: int = cab_match.start()

        cab_end: int = cab_bgn + int.from_bytes(input_data[cab_bgn + 0x8:cab_bgn + 0xC], 'little')

        cab_tag: str = f'[0x{cab_bgn:06X}-0x{cab_end:06X}]'

        cab_path: str = os.path.join(extract_path, f'CAB_{cab_tag}.cab')

        with open(cab_path, 'wb') as cab_file:
            cab_file.write(input_data[cab_bgn:cab_end])  # Store CAB archive

        if is_szip_supported(cab_path, padding, check=True):
            printer(f'Panasonic BIOS Package > PE > CAB {cab_tag}', padding)

            if szip_decompress(cab_path, extract_path, 'CAB', padding + 4, check=True) == 0:
                os.remove(cab_path)  # Successful extraction, delete CAB archive

                for extracted_file_path in get_path_files(extract_path):
                    extracted_pe_file: pefile.PE | None = get_pe_file(extracted_file_path, padding, silent=True)

                    if extracted_pe_file:
                        extracted_pe_desc: bytes = get_pe_desc(extracted_pe_file, silent=True)

                        if extracted_pe_desc.decode('utf-8', 'ignore').upper() == PAN_PE_DESC_UPD:
                            return extracted_file_path

    return ''


def panasonic_res_extract(pe_file: pefile.PE, extract_path: str, pe_name: str = '', padding: int = 0) -> bool:
    """ Extract & Decompress Panasonic BIOS Update PE RCDATA (LZNT1) """

    is_rcdata: bool = False

    # When fast_load is used, IMAGE_DIRECTORY_ENTRY_RESOURCE must be parsed prior to RCDATA Directories
    pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

    # Parse all Resource Data Directories > RCDATA (ID = 10)
    for entry in pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.struct.name == 'IMAGE_RESOURCE_DIRECTORY_ENTRY' and entry.struct.Id == 0xA:
            is_rcdata = True

            for resource in entry.directory.entries:
                res_bgn: int = resource.directory.entries[0].data.struct.OffsetToData
                res_len: int = resource.directory.entries[0].data.struct.Size
                res_end: int = res_bgn + res_len

                res_bin: bytes = pe_file.get_data(res_bgn, res_len)

                res_tag: str = f'{pe_name} [0x{res_bgn:06X}-0x{res_end:06X}]'.strip()

                res_out: str = os.path.join(extract_path, f'{res_tag}')

                printer(res_tag, padding)

                try:
                    res_raw: bytes = lznt1.decompress(res_bin[0x8:])

                    if len(res_raw) != int.from_bytes(res_bin[0x4:0x8], 'little'):
                        raise ValueError('LZNT1_DECOMPRESS_BAD_SIZE')

                    printer('Succesfull LZNT1 decompression via Dissect!', padding + 4)
                except Exception as error:  # pylint: disable=broad-except
                    logging.debug('Error: LZNT1 decompression of %s failed: %s', res_tag, error)

                    res_raw = res_bin

                    printer('Succesfull PE Resource extraction!', padding + 4)

                # Detect & Unpack AMI BIOS Guard (PFAT) BIOS image
                if is_ami_pfat(res_raw):
                    pfat_dir: str = os.path.join(extract_path, res_tag)

                    parse_pfat_file(res_raw, pfat_dir, padding + 8)
                else:
                    if is_pe_file(res_raw):
                        res_ext: str = 'exe'
                    elif res_raw.startswith(b'[') and res_raw.endswith((b'\x0D\x0A', b'\x0A')):
                        res_ext = 'txt'
                    else:
                        res_ext = 'bin'

                    if res_ext == 'txt':
                        printer(new_line=False)

                        for line in io.BytesIO(res_raw).readlines():
                            line_text: str = line.decode('utf-8', 'ignore').rstrip()

                            printer(line_text, padding + 8, new_line=False)

                    with open(f'{res_out}.{res_ext}', 'wb') as out_file:
                        out_file.write(res_raw)

    return is_rcdata


def panasonic_img_extract(pe_file: pefile.PE, extract_path: str, pe_name: str = '', padding: int = 0) -> bool:
    """ Extract Panasonic BIOS Update PE Data when RCDATA is not available """

    pe_data: bytes = bytes(pe_file.__data__)

    sec_bgn: int = pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY[
        'IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress

    img_bgn: int = pe_file.OPTIONAL_HEADER.BaseOfData + pe_file.OPTIONAL_HEADER.SizeOfInitializedData
    img_end: int = sec_bgn or len(pe_data)

    img_bin: bytes = pe_data[img_bgn:img_end]

    img_tag: str = f'{pe_name} [0x{img_bgn:X}-0x{img_end:X}]'.strip()

    img_out: str = os.path.join(extract_path, f'{img_tag}.bin')

    printer(img_tag, padding)

    with open(img_out, 'wb') as out_img:
        out_img.write(img_bin)

    printer('Succesfull PE Data extraction!', padding + 4)

    return bool(img_bin)


def panasonic_pkg_extract(input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> int:
    """ Parse & Extract Panasonic BIOS Package PE """

    upd_pe_file: pefile.PE | None = get_pe_file(input_object, padding)

    upd_pe_name: str = panasonic_pkg_name(input_object)

    printer(f'Panasonic BIOS Package > PE ({upd_pe_name})\n'.replace(' ()', ''), padding)

    show_pe_info(upd_pe_file, padding + 4)

    make_dirs(extract_path, delete=True)

    upd_pe_path: str = panasonic_cab_extract(input_object, extract_path, padding + 8)

    upd_padding: int = padding

    if upd_pe_path:
        upd_padding = padding + 16

        upd_pe_name = panasonic_pkg_name(upd_pe_path)

        printer(f'Panasonic BIOS Update > PE ({upd_pe_name})\n'.replace(' ()', ''), upd_padding)

        upd_pe_file = get_pe_file(upd_pe_path, upd_padding)

        show_pe_info(upd_pe_file, upd_padding + 4)

        os.remove(upd_pe_path)

    is_upd_extracted: bool = panasonic_res_extract(upd_pe_file, extract_path, upd_pe_name, upd_padding + 8)

    if not is_upd_extracted:
        is_upd_extracted = panasonic_img_extract(upd_pe_file, extract_path, upd_pe_name, upd_padding + 8)

    return 0 if is_upd_extracted else 1


PAN_PE_DESC_UNP: str = 'UNPACK UTILITY'
PAN_PE_DESC_UPD: str = 'BIOS UPDATE'

if __name__ == '__main__':
    BIOSUtility(title=TITLE, check=is_panasonic_pkg, main=panasonic_pkg_extract).run_utility()
