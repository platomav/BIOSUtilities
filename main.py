#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import os

from argparse import ArgumentParser, Namespace
from typing import Any, Final

from biosutilities import __version__

from biosutilities.ami_pfat_extract import AmiPfatExtract
from biosutilities.ami_ucp_extract import AmiUcpExtract
from biosutilities.apple_efi_id import AppleEfiIdentify
from biosutilities.apple_efi_im4p import AppleEfiIm4pSplit
from biosutilities.apple_efi_pbzx import AppleEfiPbzxExtract
from biosutilities.apple_efi_pkg import AppleEfiPkgExtract
from biosutilities.award_bios_extract import AwardBiosExtract
from biosutilities.dell_pfs_extract import DellPfsExtract
from biosutilities.fujitsu_sfx_extract import FujitsuSfxExtract
from biosutilities.fujitsu_upc_extract import FujitsuUpcExtract
from biosutilities.insyde_ifd_extract import InsydeIfdExtract
from biosutilities.panasonic_bios_extract import PanasonicBiosExtract
from biosutilities.phoenix_tdk_extract import PhoenixTdkExtract
from biosutilities.portwell_efi_extract import PortwellEfiExtract
from biosutilities.toshiba_com_extract import ToshibaComExtract
from biosutilities.vaio_package_extract import VaioPackageExtract

from biosutilities.common.paths import (delete_dirs, extract_folder, is_access, is_dir, is_empty_dir, is_file,
                                        path_files, path_name, path_parent, real_path, runtime_root)
from biosutilities.common.system import python_version, printer, system_platform
from biosutilities.common.texts import remove_quotes, to_boxed, to_ordinal


class BIOSUtilities:
    """ Main BIOSUtilities class """

    MAX_FAT32_ITEMS: Final[int] = 65535

    MIN_PYTHON_VER: Final[tuple[int, int]] = (3, 10)

    def __init__(self) -> None:
        main_argparser: ArgumentParser = ArgumentParser(allow_abbrev=False)

        main_argparser.add_argument('paths', nargs='*')
        main_argparser.add_argument('-e', '--auto-exit', help='do not pause on exit', action='store_true')
        main_argparser.add_argument('-o', '--output-dir', help='extraction directory')

        self.main_arguments: Namespace = main_argparser.parse_args()

        self._input_files: list[str] = []

        self._output_path: str = ''

    def _setup_input_files(self, padding: int = 0) -> None:
        self._input_files = []

        input_paths: list[str] = self.main_arguments.paths

        if not input_paths:
            input_paths = [remove_quotes(in_text=input(f'\n{" " * padding}Enter input file or directory path: '))]

        for input_path in [input_path for input_path in input_paths if input_path]:
            input_path_real: str = real_path(in_path=input_path)

            if is_dir(in_path=input_path_real):
                for input_file in path_files(in_path=input_path_real):
                    if is_file(in_path=input_file) and is_access(in_path=input_file):
                        self._input_files.append(input_file)
            elif is_file(in_path=input_path_real) and is_access(in_path=input_path_real):
                self._input_files.append(input_path_real)

    def _setup_output_dir(self, padding: int = 0) -> None:
        self._output_path = ''

        output_path: str = self.main_arguments.output_dir

        if not output_path:
            output_path = remove_quotes(in_text=input(f'\n{" " * padding}Enter output directory path: '))

            if not output_path and self._input_files:
                output_path = str(path_parent(in_path=self._input_files[0]))

        if output_path and is_dir(in_path=output_path) and is_access(in_path=output_path):
            self._output_path = output_path
        else:
            self._output_path = runtime_root()

    def _check_sys_py(self) -> None:
        """ Check Python Version """

        sys_py: tuple = python_version()

        if sys_py < self.MIN_PYTHON_VER:
            min_py_str: str = '.'.join(map(str, self.MIN_PYTHON_VER))
            sys_py_str: str = '.'.join(map(str, sys_py[:2]))

            raise RuntimeError(f'Python >= {min_py_str} required, not {sys_py_str}')

    @staticmethod
    def _check_sys_os() -> None:
        """ Check OS Platform """

        os_tag, is_win, is_lnx = system_platform()

        if not (is_win or is_lnx):
            raise OSError(f'Unsupported operating system: {os_tag}')

    def run_main(self, padding: int = 0) -> bool:
        """ Run main """

        self._check_sys_py()

        self._check_sys_os()

        self._setup_input_files(padding=padding)

        self._setup_output_dir(padding=padding)

        exit_code: int = len(self._input_files)

        utilities_classes: list[Any] = [
            AmiUcpExtract, AmiPfatExtract, InsydeIfdExtract, DellPfsExtract, PhoenixTdkExtract, PanasonicBiosExtract,
            VaioPackageExtract, PortwellEfiExtract, ToshibaComExtract, FujitsuSfxExtract, FujitsuUpcExtract,
            AwardBiosExtract, AppleEfiPkgExtract, AppleEfiPbzxExtract, AppleEfiIm4pSplit, AppleEfiIdentify
        ]

        for input_file in self._input_files:
            input_name: str = path_name(in_path=input_file, limit=True)

            printer(message=f'{input_name}\n', padding=padding)

            for utility_class in utilities_classes:
                extract_path: str = os.path.join(self._output_path, extract_folder(in_path=input_name))

                if is_dir(in_path=extract_path):
                    for suffix in range(2, self.MAX_FAT32_ITEMS):
                        renamed_path: str = f'{os.path.normpath(extract_path)}_{to_ordinal(in_number=suffix)}'

                        if not is_dir(in_path=renamed_path):
                            extract_path = renamed_path

                            break

                utility: Any = utility_class(input_object=input_file, extract_path=extract_path, padding=padding + 8)

                if not utility.check_format():
                    continue

                printer(message=to_boxed(in_text=f'{utility.TITLE} v{__version__}'),
                        new_line=False, padding=padding + 4)

                is_parsed_format: bool = utility.parse_format()

                is_empty_output: bool = is_empty_dir(in_path=extract_path)

                if is_empty_output:
                    delete_dirs(in_path=extract_path)

                if is_parsed_format and not is_empty_output:
                    exit_code -= 1

                    break

        printer(message=None, new_line=False)

        if not self.main_arguments.auto_exit:
            input('Press any key to exit...')

        return exit_code == 0


if __name__ == '__main__':
    BIOSUtilities().run_main()
