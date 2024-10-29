#!/usr/bin/env python3 -B
# coding=utf-8

"""
Apple EFI PKG
Apple EFI Package Extractor
Copyright (C) 2019-2024 Plato Mavropoulos
"""

import os

from biosutilities.common.compression import is_szip_supported, szip_decompress
from biosutilities.common.paths import (copy_file, delete_dirs, delete_file, extract_folder, is_access, is_dir,
                                        is_file, make_dirs, path_files, path_name, path_suffixes, runtime_root)
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility

from biosutilities.apple_efi_id import AppleEfiIdentify, EFI_EXTENSIONS
from biosutilities.apple_efi_im4p import AppleEfiIm4pSplit
from biosutilities.apple_efi_pbzx import AppleEfiPbzxExtract


class AppleEfiPkgExtract(BIOSUtility):
    """ Apple EFI Package Extractor """

    TITLE: str = 'Apple EFI Package Extractor'

    def check_format(self) -> bool:
        """ Check if input is Apple EFI PKG package """

        is_apple_efi_pkg: bool = False

        if isinstance(self.input_object, str) and is_file(in_path=self.input_object):
            input_path: str = self.input_object
        else:
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_PKG_INPUT_BUFFER_CHECK.bin')

            with open(input_path, 'wb') as input_path_object:
                input_path_object.write(self.input_buffer)

        for pkg_type in ('XAR', 'TAR', 'DMG'):
            if is_szip_supported(in_path=input_path, args=[f'-t{pkg_type}:s0']):
                is_apple_efi_pkg = True

                break

        if input_path != self.input_object:
            delete_file(in_path=input_path)

        return is_apple_efi_pkg

    def parse_format(self) -> bool:
        """ Parse & Extract Apple EFI PKG packages """

        if isinstance(self.input_object, str) and is_file(in_path=self.input_object):
            input_path: str = self.input_object
        else:
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_PKG_INPUT_BUFFER_PARSE.bin')

            with open(input_path, 'wb') as input_path_object:
                input_path_object.write(self.input_buffer)

        working_dir: str = os.path.join(self.extract_path, 'temp')

        make_dirs(in_path=working_dir)

        for pkg_type in ('XAR', 'TAR', 'DMG'):
            if is_szip_supported(in_path=input_path, args=[f'-t{pkg_type}']):
                if szip_decompress(in_path=input_path, out_path=working_dir, in_name=pkg_type, padding=self.padding,
                                   args=None if pkg_type == 'DMG' else [f'-t{pkg_type}']):
                    break
        else:
            return False

        if input_path != self.input_object:
            delete_file(in_path=input_path)

        for work_file in path_files(in_path=working_dir):
            if is_file(in_path=work_file) and is_access(in_path=work_file):
                self._pbzx_zip(input_path=work_file, padding=self.padding + 4)
                self._gzip_cpio(input_path=work_file, padding=self.padding + 4)
                self._dmg_zip(input_path=work_file, padding=self.padding + 4)
                self._xar_gzip(input_path=work_file, padding=self.padding + 4)

        delete_dirs(in_path=working_dir)

        return True

    def _xar_gzip(self, input_path: str, padding: int = 0) -> None:
        """ XAR/TAR > GZIP """

        for pkg_type in ('XAR', 'TAR'):
            if is_szip_supported(in_path=input_path, args=[f'-t{pkg_type}']):
                pkg_path: str = extract_folder(in_path=input_path, suffix=f'_{pkg_type.lower()}_gzip')

                if szip_decompress(in_path=input_path, out_path=pkg_path, in_name=pkg_type,
                                   padding=padding, args=[f'-t{pkg_type}']):
                    for pkg_file in path_files(in_path=pkg_path):
                        if is_file(in_path=pkg_file) and is_access(in_path=pkg_file):
                            self._gzip_cpio(input_path=pkg_file, padding=padding + 4)

                break

    def _dmg_zip(self, input_path: str, padding: int = 0) -> None:
        """ DMG > ZIP """

        if is_szip_supported(in_path=input_path, args=['-tDMG']):
            dmg_path: str = extract_folder(in_path=input_path, suffix='_dmg_zip')

            if szip_decompress(in_path=input_path, out_path=dmg_path, in_name='DMG', padding=padding, args=None):
                for dmg_file in path_files(in_path=dmg_path):
                    if is_file(in_path=dmg_file) and is_access(in_path=dmg_file):
                        if is_szip_supported(in_path=dmg_file, args=['-tZIP']):
                            zip_path: str = extract_folder(in_path=dmg_file)

                            if szip_decompress(in_path=dmg_file, out_path=zip_path, in_name='ZIP',
                                               padding=padding + 4, args=['-tZIP']):
                                for zip_file in path_files(in_path=zip_path):
                                    self._im4p_id(input_path=zip_file, padding=padding + 8)

    def _pbzx_zip(self, input_path: str, padding: int = 0) -> None:
        """ PBZX > ZIP """

        pbzx_path: str = extract_folder(in_path=input_path, suffix='_pbzx_zip')

        pbzx_module: AppleEfiPbzxExtract = AppleEfiPbzxExtract(
            input_object=input_path, extract_path=pbzx_path, padding=padding + 4)

        if pbzx_module.check_format():
            printer(message=f'Extracting PBZX via {pbzx_module.TITLE}', padding=padding)

            if pbzx_module.parse_format():
                printer(message=f'Successful PBZX extraction via {pbzx_module.TITLE}!', padding=padding)

                for pbzx_file in path_files(in_path=pbzx_path):
                    if is_file(in_path=pbzx_file) and is_access(in_path=pbzx_file):
                        if is_szip_supported(in_path=pbzx_file, args=['-tZIP']):
                            zip_path: str = extract_folder(in_path=pbzx_file)

                            if szip_decompress(in_path=pbzx_file, out_path=zip_path, in_name='ZIP',
                                               padding=padding + 4, args=['-tZIP']):
                                for zip_file in path_files(in_path=zip_path):
                                    self._im4p_id(input_path=zip_file, padding=padding + 8)

    def _gzip_cpio(self, input_path: str, padding: int = 0) -> None:
        """ GZIP > CPIO """

        if is_szip_supported(in_path=input_path, args=['-tGZIP']):
            gzip_path: str = extract_folder(in_path=input_path, suffix='_gzip_cpio')

            if szip_decompress(in_path=input_path, out_path=gzip_path, in_name='GZIP',
                               padding=padding, args=['-tGZIP']):
                for gzip_file in path_files(in_path=gzip_path):
                    if is_file(in_path=gzip_file) and is_access(in_path=gzip_file):
                        if is_szip_supported(in_path=gzip_file, args=['-tCPIO']):
                            cpio_path: str = extract_folder(in_path=gzip_file)

                            if szip_decompress(in_path=gzip_file, out_path=cpio_path, in_name='CPIO',
                                               padding=padding + 4, args=['-tCPIO']):
                                for cpio_file in path_files(in_path=cpio_path):
                                    self._im4p_id(input_path=cpio_file, padding=padding + 8)

    def _im4p_id(self, input_path: str, padding: int = 0) -> None:
        """ Split IM4P (if applicable), identify and copy EFI """

        if path_suffixes(in_path=input_path)[-1].lower() not in EFI_EXTENSIONS:
            return None

        if not (is_file(in_path=input_path) and is_access(in_path=input_path)):
            return None

        working_dir: str = extract_folder(in_path=input_path)

        if not AppleEfiIdentify(input_object=input_path, extract_path=working_dir).check_format():
            return None

        printer(message=path_name(in_path=input_path), padding=padding)

        im4p_module: AppleEfiIm4pSplit = AppleEfiIm4pSplit(
            input_object=input_path, extract_path=working_dir, padding=padding + 8)

        if im4p_module.check_format():
            printer(message=f'Splitting IM4P via {im4p_module.TITLE}', padding=padding + 4)

            im4p_module.parse_format()

        for efi_path in path_files(in_path=working_dir) if is_dir(in_path=working_dir) else [input_path]:
            if is_file(in_path=efi_path) and is_access(in_path=efi_path):
                efi_id_module: AppleEfiIdentify = AppleEfiIdentify(
                    input_object=efi_path, extract_path=extract_folder(in_path=efi_path), padding=padding + 8)

                if efi_id_module.check_format():
                    printer(message=f'Identifying EFI via {efi_id_module.TITLE}', padding=padding + 4)

                    if efi_id_module.parse_format():
                        efi_path_final: str = os.path.join(self.extract_path, efi_id_module.efi_file_name)

                        copy_file(in_path=efi_path, out_path=efi_path_final, metadata=True)

        delete_dirs(in_path=working_dir)

        return None
