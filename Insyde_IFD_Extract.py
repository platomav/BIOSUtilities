#!/usr/bin/env python3 -B
# coding=utf-8

"""
Insyde IFD Extract
Insyde iFlash/iFdPacker Extractor
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import ctypes
import os

from common.comp_szip import is_szip_supported, szip_decompress
from common.path_ops import get_extract_path, get_path_files, make_dirs, safe_name
from common.patterns import PAT_INSYDE_IFL, PAT_INSYDE_SFX
from common.struct_ops import Char, get_struct, UInt32
from common.system import printer
from common.templates import BIOSUtility
from common.text_ops import file_to_bytes

TITLE = 'Insyde iFlash/iFdPacker Extractor v3.0'


class IflashHeader(ctypes.LittleEndianStructure):
    """ Insyde iFlash Header """

    _pack_ = 1

    # noinspection PyTypeChecker
    _fields_ = [
        ('Signature',       Char * 8),      # 0x00 $_IFLASH
        ('ImageTag',        Char * 8),      # 0x08
        ('TotalSize',       UInt32),        # 0x10 from header end
        ('ImageSize',       UInt32),        # 0x14 from header end
        # 0x18
    ]

    def _get_padd_len(self) -> int:
        return self.TotalSize - self.ImageSize

    def get_image_tag(self) -> str:
        """ Get Insyde iFlash image tag """

        return self.ImageTag.decode('utf-8', 'ignore').strip('_')

    def struct_print(self, padd: int) -> None:
        """ Display structure information """

        printer(['Signature :', self.Signature.decode('utf-8')], padd, False)
        printer(['Image Name:', self.get_image_tag()], padd, False)
        printer(['Image Size:', f'0x{self.ImageSize:X}'], padd, False)
        printer(['Total Size:', f'0x{self.TotalSize:X}'], padd, False)
        printer(['Padd Size :', f'0x{self._get_padd_len():X}'], padd, False)


def is_insyde_ifd(input_object: str | bytes | bytearray) -> bool:
    """ Check if input is Insyde iFlash/iFdPacker Update image """

    input_buffer: bytes = file_to_bytes(input_object)

    is_ifl: bool = bool(insyde_iflash_detect(input_buffer))

    is_sfx: bool = bool(PAT_INSYDE_SFX.search(input_buffer))

    return is_ifl or is_sfx


def insyde_ifd_extract(input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> int:
    """ Parse & Extract Insyde iFlash/iFdPacker Update images """

    input_buffer: bytes = file_to_bytes(input_object)

    iflash_code: int = insyde_iflash_extract(input_buffer, extract_path, padding)

    ifdpack_path: str = os.path.join(extract_path, 'Insyde iFdPacker SFX')

    ifdpack_code: int = insyde_packer_extract(input_buffer, ifdpack_path, padding)

    return iflash_code and ifdpack_code


def insyde_iflash_detect(input_buffer: bytes) -> list:
    """ Detect Insyde iFlash Update image """

    iflash_match_all: list = []
    iflash_match_nan: list = [0x0, 0xFFFFFFFF]

    for iflash_match in PAT_INSYDE_IFL.finditer(input_buffer):
        ifl_bgn: int = iflash_match.start()

        if len(input_buffer[ifl_bgn:]) <= INS_IFL_LEN:
            continue

        ifl_hdr = get_struct(input_buffer, ifl_bgn, IflashHeader)

        if ifl_hdr.TotalSize in iflash_match_nan \
                or ifl_hdr.ImageSize in iflash_match_nan \
                or ifl_hdr.TotalSize < ifl_hdr.ImageSize \
                or ifl_bgn + INS_IFL_LEN + ifl_hdr.TotalSize > len(input_buffer):
            continue

        iflash_match_all.append([ifl_bgn, ifl_hdr])

    return iflash_match_all


def insyde_iflash_extract(input_buffer: bytes, extract_path: str, padding: int = 0) -> int:
    """ Extract Insyde iFlash Update image """

    insyde_iflash_all: list = insyde_iflash_detect(input_buffer)

    if not insyde_iflash_all:
        return 127

    printer('Detected Insyde iFlash Update image!', padding)

    make_dirs(extract_path, delete=True)

    exit_codes: list = []

    for insyde_iflash in insyde_iflash_all:
        exit_code: int = 0

        ifl_bgn, ifl_hdr = insyde_iflash

        img_bgn: int = ifl_bgn + INS_IFL_LEN
        img_end: int = img_bgn + ifl_hdr.ImageSize
        img_bin: bytes = input_buffer[img_bgn:img_end]

        if len(img_bin) != ifl_hdr.ImageSize:
            exit_code = 1

        img_val: list = [ifl_hdr.get_image_tag(), 'bin']
        img_tag, img_ext = INS_IFL_IMG.get(img_val[0], img_val)

        img_name: str = f'{img_tag} [0x{img_bgn:08X}-0x{img_end:08X}]'

        printer(f'{img_name}\n', padding + 4)

        ifl_hdr.struct_print(padding + 8)

        if img_val == [img_tag, img_ext]:
            printer(f'Note: Detected new Insyde iFlash tag {img_tag}!', padding + 12, pause=True)

        out_name: str = f'{img_name}.{img_ext}'

        out_path: str = os.path.join(extract_path, safe_name(out_name))

        with open(out_path, 'wb') as out_image:
            out_image.write(img_bin)

        printer(f'Succesfull Insyde iFlash > {img_tag} extraction!', padding + 12)

        exit_codes.append(exit_code)

    return sum(exit_codes)


def insyde_packer_extract(input_buffer: bytes, extract_path: str, padding: int = 0) -> int:
    """ Extract Insyde iFdPacker 7-Zip SFX 7z Update image """

    match_sfx = PAT_INSYDE_SFX.search(input_buffer)

    if not match_sfx:
        return 127

    printer('Detected Insyde iFdPacker Update image!', padding)

    make_dirs(extract_path, delete=True)

    sfx_buffer: bytearray = bytearray(input_buffer[match_sfx.end() - 0x5:])

    if sfx_buffer[:0x5] == b'\x6E\xF4\x79\x5F\x4E':
        printer('Detected Insyde iFdPacker > 7-Zip SFX > Obfuscation!', padding + 4)

        for index, byte in enumerate(sfx_buffer):
            sfx_buffer[index] = byte // 2 + (128 if byte % 2 else 0)

        printer('Removed Insyde iFdPacker > 7-Zip SFX > Obfuscation!', padding + 8)

    printer('Extracting Insyde iFdPacker > 7-Zip SFX archive...', padding + 4)

    if bytes(INS_SFX_PWD, 'utf-16le') in input_buffer[:match_sfx.start()]:
        printer('Detected Insyde iFdPacker > 7-Zip SFX > Password!', padding + 8)

        printer(INS_SFX_PWD, padding + 12)

    sfx_path: str = os.path.join(extract_path, 'Insyde_iFdPacker_SFX.7z')

    with open(sfx_path, 'wb') as sfx_file:
        sfx_file.write(sfx_buffer)

    if is_szip_supported(sfx_path, padding + 8, args=[f'-p{INS_SFX_PWD}'], check=True):
        if szip_decompress(sfx_path, extract_path, 'Insyde iFdPacker > 7-Zip SFX',
                           padding + 8, args=[f'-p{INS_SFX_PWD}'], check=True) == 0:
            os.remove(sfx_path)
        else:
            return 125
    else:
        return 126

    exit_codes = []

    for sfx_file in get_path_files(extract_path):
        if is_insyde_ifd(sfx_file):
            printer(f'{os.path.basename(sfx_file)}', padding + 12)

            ifd_code: int = insyde_ifd_extract(sfx_file, get_extract_path(sfx_file), padding + 16)

            exit_codes.append(ifd_code)

    return sum(exit_codes)


# Insyde iFdPacker known 7-Zip SFX Password
INS_SFX_PWD: str = 'Y`t~i!L@i#t$U%h^s7A*l(f)E-d=y+S_n?i'

# Insyde iFlash known Image Names
INS_IFL_IMG: dict = {
    'BIOSCER': ['Certificate', 'bin'],
    'BIOSCR2': ['Certificate 2nd', 'bin'],
    'BIOSIMG': ['BIOS-UEFI', 'bin'],
    'DRV_IMG': ['isflash', 'efi'],
    'EC_IMG': ['Embedded Controller', 'bin'],
    'INI_IMG': ['platform', 'ini'],
    'ME_IMG': ['Management Engine', 'bin'],
    'OEM_ID': ['OEM Identifier', 'bin'],
}

# Get common ctypes Structure Sizes
INS_IFL_LEN: int = ctypes.sizeof(IflashHeader)

if __name__ == '__main__':
    BIOSUtility(title=TITLE, check=is_insyde_ifd, main=insyde_ifd_extract).run_utility()
