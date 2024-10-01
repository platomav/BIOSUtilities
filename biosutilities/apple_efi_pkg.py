#!/usr/bin/env python3 -B
# coding=utf-8

"""
Apple EFI PKG
Apple EFI Package Extractor
Copyright (C) 2019-2024 Plato Mavropoulos
"""

import os

from biosutilities.common.compression import is_szip_supported, szip_decompress
from biosutilities.common.paths import (copy_file, delete_dirs, extract_folder, path_files,
                                        make_dirs, path_name, path_parent, runtime_root)
from biosutilities.common.patterns import PAT_APPLE_PKG_TAR, PAT_APPLE_PKG_XAR
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes

from biosutilities.apple_efi_id import AppleEfiIdentify
from biosutilities.apple_efi_im4p import AppleEfiIm4pSplit
from biosutilities.apple_efi_pbzx import AppleEfiPbzxExtract


class AppleEfiPkgExtract(BIOSUtility):
    """ Apple EFI Package Extractor """

    TITLE: str = 'Apple EFI Package Extractor'

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is Apple EFI PKG package """

        is_apple_efi_pkg: bool = False

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        if isinstance(input_object, str) and os.path.isfile(path=input_object):
            input_path: str = input_object
        else:
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_PKG_INPUT_BUFFER_CHECK.bin')

            with open(file=input_path, mode='wb') as input_path_object:
                input_path_object.write(input_buffer)

        if is_szip_supported(in_path=input_path, args=['-tXAR']):
            if bool(PAT_APPLE_PKG_XAR.search(string=input_buffer, endpos=4)):
                is_apple_efi_pkg = True
        elif is_szip_supported(in_path=input_path, args=['-tTAR']):
            if bool(PAT_APPLE_PKG_TAR.search(string=input_buffer)):
                is_apple_efi_pkg = True

        if input_path != input_object:
            os.remove(path=input_path)

        return is_apple_efi_pkg

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> int:
        """ Parse & Extract Apple EFI PKG packages """

        if isinstance(input_object, str) and os.path.isfile(path=input_object):
            input_path: str = input_object
        else:
            input_path = os.path.join(runtime_root(), 'APPLE_EFI_PKG_INPUT_BUFFER_PARSE.bin')

            with open(file=input_path, mode='wb') as input_path_object:
                input_path_object.write(file_to_bytes(in_object=input_object))

        make_dirs(in_path=extract_path, delete=True)

        working_dir: str = os.path.join(extract_path, 'temp')

        for pkg_type in ('XAR', 'TAR'):
            if is_szip_supported(in_path=input_path, padding=padding, args=[f'-t{pkg_type}']):
                if szip_decompress(in_path=input_path, out_path=working_dir, in_name=pkg_type, padding=padding,
                                   args=[f'-t{pkg_type}'], check=True) == 0:
                    break
        else:
            return 1

        if input_path != input_object:
            os.remove(path=input_path)

        for work_file in path_files(in_path=working_dir):
            self._pbzx_zip(input_path=work_file, extract_path=extract_path, padding=padding + 4)
            self._gzip_cpio(input_path=work_file, extract_path=extract_path, padding=padding + 4)
            self._tar_gzip(input_path=work_file, extract_path=extract_path, padding=padding + 4)

        delete_dirs(in_path=working_dir)

        return 0

    def _tar_gzip(self, input_path: str, extract_path: str, padding: int = 0) -> None:
        """ TAR > GZIP """

        if is_szip_supported(in_path=input_path, padding=padding, args=['-tTAR']):
            tar_path: str = extract_folder(in_path=input_path)

            if szip_decompress(in_path=input_path, out_path=tar_path, in_name='TAR', padding=padding,
                               args=['-tTAR'], check=False) == 0:
                for tar_file in path_files(in_path=tar_path):
                    self._gzip_cpio(input_path=tar_file, extract_path=extract_path, padding=padding + 4)

    def _pbzx_zip(self, input_path: str, extract_path: str, padding: int = 0) -> None:
        """ PBZX > ZIP """

        pbzx_module: AppleEfiPbzxExtract = AppleEfiPbzxExtract()

        if pbzx_module.check_format(input_object=input_path):
            printer(message=f'Extracting PBZX via {pbzx_module.title}', padding=padding)

            pbzx_path: str = extract_folder(in_path=input_path)

            if pbzx_module.parse_format(input_object=input_path, extract_path=pbzx_path, padding=padding + 4) == 0:
                printer(message=f'Successful PBZX extraction via {pbzx_module.title}!', padding=padding)

                for pbzx_file in path_files(in_path=pbzx_path):
                    if is_szip_supported(in_path=pbzx_file, padding=padding + 4, args=['-tZIP']):
                        zip_path: str = extract_folder(in_path=pbzx_file)

                        if szip_decompress(in_path=pbzx_file, out_path=zip_path, in_name='ZIP',
                                           padding=padding + 4, args=['-tZIP'], check=False) == 0:
                            for zip_file in path_files(in_path=zip_path):
                                self._im4p_id(input_path=zip_file, output_path=extract_path, padding=padding + 8)

    def _gzip_cpio(self, input_path: str, extract_path: str, padding: int = 0) -> None:
        """ GZIP > CPIO """

        if is_szip_supported(in_path=input_path, padding=padding, args=['-tGZIP']):
            gzip_path: str = extract_folder(in_path=input_path)

            if szip_decompress(in_path=input_path, out_path=gzip_path, in_name='GZIP', padding=padding,
                               args=['-tGZIP'], check=True) == 0:
                for gzip_file in path_files(in_path=gzip_path):
                    if is_szip_supported(in_path=gzip_file, padding=padding + 4, args=['-tCPIO']):
                        cpio_path: str = extract_folder(in_path=gzip_file)

                        if szip_decompress(in_path=gzip_file, out_path=cpio_path, in_name='CPIO',
                                           padding=padding + 4, args=['-tCPIO'], check=False) == 0:
                            for cpio_file in path_files(in_path=cpio_path):
                                self._im4p_id(input_path=cpio_file, output_path=extract_path, padding=padding + 8)

    @staticmethod
    def _im4p_id(input_path: str, output_path: str, padding: int = 0) -> None:
        """ Split IM4P (if applicable), identify and rename EFI """

        if not AppleEfiIdentify().check_format(input_object=input_path):
            return None

        input_name: str = path_name(in_path=input_path)

        printer(message=input_name, padding=padding)

        working_dir: str = extract_folder(in_path=input_path)

        im4p_module: AppleEfiIm4pSplit = AppleEfiIm4pSplit()

        if im4p_module.check_format(input_object=input_path):
            printer(message=f'Splitting IM4P via {im4p_module.title}', padding=padding + 4)

            im4p_module.parse_format(input_object=input_path, extract_path=working_dir, padding=padding + 8)
        else:
            make_dirs(in_path=working_dir, delete=True)

            copy_file(in_path=input_path, out_path=working_dir, metadata=True)

        for efi_source in path_files(in_path=working_dir):
            efi_id_module: AppleEfiIdentify = AppleEfiIdentify()

            if efi_id_module.check_format(input_object=efi_source):
                printer(message=f'Identifying EFI via {efi_id_module.title}', padding=padding + 4)

                efi_id_exit: int = efi_id_module.parse_format(
                    input_object=efi_source, extract_path=extract_folder(in_path=efi_source), padding=padding + 8)

                if efi_id_exit == 0:
                    efi_dest: str = os.path.join(path_parent(in_path=efi_source), efi_id_module.efi_name_id)

                    os.rename(src=efi_source, dst=efi_dest)

        for efi_final in path_files(in_path=working_dir):
            copy_file(in_path=efi_final, out_path=output_path, metadata=True)

        delete_dirs(in_path=working_dir)

        return None


if __name__ == '__main__':
    AppleEfiPkgExtract().run_utility()
