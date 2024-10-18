#!/usr/bin/env python3 -B
# coding=utf-8

"""
Insyde IFD Extract
Insyde iFlash/iFdPacker Extractor
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import ctypes
import os
import re

from typing import Any, Final

from biosutilities.common.compression import is_szip_supported, szip_decompress
from biosutilities.common.paths import (extract_folder, is_access, is_file, path_files,
                                        make_dirs, path_name, safe_name)
from biosutilities.common.patterns import PAT_INSYDE_IFL, PAT_INSYDE_SFX
from biosutilities.common.structs import CHAR, ctypes_struct, UINT32
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes


class IflashHeader(ctypes.LittleEndianStructure):
    """ Insyde iFlash Header """

    _pack_ = 1
    _fields_ = [
        ('Signature',       CHAR * 8),      # 0x00 $_IFLASH
        ('ImageTag',        CHAR * 8),      # 0x08
        ('TotalSize',       UINT32),        # 0x10 from header end
        ('ImageSize',       UINT32)         # 0x14 from header end
        # 0x18
    ]

    def _get_padd_len(self) -> int:
        return self.TotalSize - self.ImageSize

    def get_image_tag(self) -> str:
        """ Get Insyde iFlash image tag """

        return self.ImageTag.decode('utf-8', 'ignore').strip('_')

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Signature :', self.Signature.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['Image Name:', self.get_image_tag()], padding=padding, new_line=False)
        printer(message=['Image Size:', f'0x{self.ImageSize:X}'], padding=padding, new_line=False)
        printer(message=['Total Size:', f'0x{self.TotalSize:X}'], padding=padding, new_line=False)
        printer(message=['Padd Size :', f'0x{self._get_padd_len():X}'], padding=padding, new_line=False)


class InsydeIfdExtract(BIOSUtility):
    """ Insyde iFlash/iFdPacker Extractor """

    TITLE: str = 'Insyde iFlash/iFdPacker Extractor'

    # Insyde iFdPacker known 7-Zip SFX Password
    INS_SFX_PWD: Final[str] = 'Y`t~i!L@i#t$U%h^s7A*l(f)E-d=y+S_n?i'

    # Insyde iFlash known Image Names
    INS_IFL_IMG: Final[dict[str, list[str]]] = {
        'BIOSCER': ['Certificate', 'bin'],
        'BIOSCR2': ['Certificate 2nd', 'bin'],
        'BIOSIMG': ['BIOS-UEFI', 'bin'],
        'DRV_IMG': ['isflash', 'efi'],
        'EC_IMG': ['Embedded Controller', 'bin'],
        'INI_IMG': ['platform', 'ini'],
        'IOM_IMG': ['IO Manageability', 'bin'],
        'ISH_IMG': ['Integrated Sensor Hub', 'bin'],
        'ME_IMG': ['Management Engine', 'bin'],
        'OEM_ID': ['OEM Identifier', 'bin'],
        'PDT_IMG': ['Platform Descriptor Table', 'bin'],
        'TBT_IMG': ['Integrated Thunderbolt', 'bin']
    }

    # Get common ctypes Structure Sizes
    INS_IFL_LEN: Final[int] = ctypes.sizeof(IflashHeader)

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Insyde iFlash/iFdPacker Update image """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        if bool(self._insyde_iflash_detect(input_buffer=input_buffer)):
            return True

        if bool(PAT_INSYDE_SFX.search(input_buffer)):
            return True

        return False

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool:
        """ Parse & Extract Insyde iFlash/iFdPacker Update images """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        iflash_code: int = self._insyde_iflash_extract(input_buffer=input_buffer, extract_path=extract_path,
                                                       padding=padding)

        ifdpack_path: str = os.path.join(extract_path, 'Insyde iFdPacker SFX')

        ifdpack_code: int = self._insyde_packer_extract(input_buffer=input_buffer, extract_path=ifdpack_path,
                                                        padding=padding)

        return (iflash_code and ifdpack_code) == 0

    def _insyde_iflash_detect(self, input_buffer: bytes) -> list:
        """ Detect Insyde iFlash Update image """

        iflash_match_all: list = []
        iflash_match_nan: list = [0x0, 0xFFFFFFFF]

        for iflash_match in PAT_INSYDE_IFL.finditer(input_buffer):
            ifl_bgn: int = iflash_match.start()

            if len(input_buffer[ifl_bgn:]) <= self.INS_IFL_LEN:
                continue

            ifl_hdr: Any = ctypes_struct(buffer=input_buffer, start_offset=ifl_bgn, class_object=IflashHeader)

            if ifl_hdr.TotalSize in iflash_match_nan \
                    or ifl_hdr.ImageSize in iflash_match_nan \
                    or ifl_hdr.TotalSize < ifl_hdr.ImageSize \
                    or ifl_bgn + self.INS_IFL_LEN + ifl_hdr.TotalSize > len(input_buffer):
                continue

            iflash_match_all.append([ifl_bgn, ifl_hdr])

        return iflash_match_all

    def _insyde_iflash_extract(self, input_buffer: bytes, extract_path: str, padding: int = 0) -> int:
        """ Extract Insyde iFlash Update image """

        insyde_iflash_all: list = self._insyde_iflash_detect(input_buffer=input_buffer)

        if not insyde_iflash_all:
            return 127

        printer(message='Detected Insyde iFlash Update image!', padding=padding)

        make_dirs(in_path=extract_path, delete=True)

        exit_codes: list = []

        for insyde_iflash in insyde_iflash_all:
            exit_code: int = 0

            ifl_bgn, ifl_hdr = insyde_iflash

            img_bgn: int = ifl_bgn + self.INS_IFL_LEN
            img_end: int = img_bgn + ifl_hdr.ImageSize
            img_bin: bytes = input_buffer[img_bgn:img_end]

            if len(img_bin) != ifl_hdr.ImageSize:
                exit_code = 1

            img_val: list = [ifl_hdr.get_image_tag(), 'bin']
            img_tag, img_ext = self.INS_IFL_IMG.get(img_val[0], img_val)

            img_name: str = f'{img_tag} [0x{img_bgn:08X}-0x{img_end:08X}]'

            printer(message=f'{img_name}\n', padding=padding + 4)

            ifl_hdr.struct_print(padding=padding + 8)

            if img_val == [img_tag, img_ext]:
                printer(message=f'Note: Detected new Insyde iFlash tag {img_tag}!',
                        padding=padding + 12, pause=not self.arguments.auto_exit)

            out_name: str = f'{img_name}.{img_ext}'

            out_path: str = os.path.join(extract_path, safe_name(in_name=out_name))

            with open(out_path, 'wb') as out_image:
                out_image.write(img_bin)

            printer(message=f'Successful Insyde iFlash > {img_tag} extraction!', padding=padding + 12)

            exit_codes.append(exit_code)

        return sum(exit_codes)

    def _insyde_packer_extract(self, input_buffer: bytes, extract_path: str, padding: int = 0) -> int:
        """ Extract Insyde iFdPacker 7-Zip SFX 7z Update image """

        match_sfx: re.Match[bytes] | None = PAT_INSYDE_SFX.search(input_buffer)

        if not match_sfx:
            return 127

        printer(message='Detected Insyde iFdPacker Update image!', padding=padding)

        make_dirs(in_path=extract_path, delete=True)

        sfx_buffer: bytearray = bytearray(input_buffer[match_sfx.end() - 0x5:])

        if sfx_buffer[:0x5] == b'\x6E\xF4\x79\x5F\x4E':
            printer(message='Detected Insyde iFdPacker > 7-Zip SFX > Obfuscation!', padding=padding + 4)

            for index, byte in enumerate(sfx_buffer):
                sfx_buffer[index] = byte // 2 + (128 if byte % 2 else 0)

            printer(message='Removed Insyde iFdPacker > 7-Zip SFX > Obfuscation!', padding=padding + 8)

        printer(message='Extracting Insyde iFdPacker > 7-Zip SFX archive...', padding=padding + 4)

        if bytes(self.INS_SFX_PWD, 'utf-16le') in input_buffer[:match_sfx.start()]:
            printer(message='Detected Insyde iFdPacker > 7-Zip SFX > Password!', padding=padding + 8)

            printer(message=self.INS_SFX_PWD, padding=padding + 12)

        sfx_path: str = os.path.join(extract_path, 'Insyde_iFdPacker_SFX.7z')

        with open(sfx_path, 'wb') as sfx_file_object:
            sfx_file_object.write(sfx_buffer)

        if is_szip_supported(in_path=sfx_path, padding=padding + 8, args=[f'-p{self.INS_SFX_PWD}'], silent=False):
            if szip_decompress(in_path=sfx_path, out_path=extract_path, in_name='Insyde iFdPacker > 7-Zip SFX',
                               padding=padding + 8, args=[f'-p{self.INS_SFX_PWD}'], check=True):
                os.remove(sfx_path)
            else:
                return 125
        else:
            return 126

        exit_codes: list[int] = []

        for sfx_file in path_files(in_path=extract_path):
            if is_file(in_path=sfx_file) and is_access(in_path=sfx_file):
                if self.check_format(input_object=sfx_file):
                    printer(message=path_name(in_path=sfx_file), padding=padding + 12)

                    ifd_status: int = self.parse_format(input_object=sfx_file, extract_path=extract_folder(sfx_file),
                                                        padding=padding + 16)

                    exit_codes.append(0 if ifd_status else 1)

        return sum(exit_codes)


if __name__ == '__main__':
    InsydeIfdExtract().run_utility()
