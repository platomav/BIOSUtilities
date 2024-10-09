#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import os
import sys

from argparse import ArgumentParser, Namespace
from typing import Final

from biosutilities import __version__
from biosutilities.common.paths import (delete_dirs, extract_folder, is_access, is_dir, is_file, is_empty_dir,
                                        path_files, path_name, path_parent, real_path, runtime_root)
from biosutilities.common.system import system_platform, python_version, printer
from biosutilities.common.texts import remove_quotes, to_boxed, to_ordinal


class BIOSUtility:
    """ Base utility class for BIOSUtilities """

    TITLE: str = 'BIOS Utility'

    ARGUMENTS: list[tuple[list[str], dict[str, str]]] = []

    MAX_FAT32_ITEMS: Final[int] = 65535

    MIN_PYTHON_VER: Final[tuple[int, int]] = (3, 10)

    def __init__(self, arguments: list[str] | None = None) -> None:
        self.title: str = f'{self.TITLE.strip()} v{__version__}'

        argparser: ArgumentParser = ArgumentParser(allow_abbrev=False)

        argparser.add_argument('paths', nargs='*')
        argparser.add_argument('-e', '--auto-exit', help='skip user action prompts', action='store_true')
        argparser.add_argument('-o', '--output-dir', help='output extraction directory')

        for argument in self.ARGUMENTS:
            argparser.add_argument(*argument[0], **argument[1])  # type: ignore

        sys_argv: list[str] = arguments if isinstance(arguments, list) and arguments else sys.argv[1:]

        self.arguments: Namespace = argparser.parse_known_args(sys_argv)[0]

        self._input_files: list[str] = []

        self._output_path: str = ''

    def run_utility(self, padding: int = 0) -> bool:
        """ Run utility after checking for supported format """

        self._check_sys_py()

        self._check_sys_os()

        self.show_version(padding=padding)

        self._setup_input_files(padding=padding)

        self._setup_output_dir(padding=padding)

        exit_code: int = len(self._input_files)

        for input_file in self._input_files:
            input_name: str = path_name(in_path=input_file, limit=True)

            printer(message=input_name, padding=padding + 4)

            if not self.check_format(input_object=input_file):
                printer(message='Error: This is not a supported format!', padding=padding + 8)

                continue

            extract_path: str = os.path.join(self._output_path, extract_folder(in_path=input_name))

            if is_dir(in_path=extract_path):
                for suffix in range(2, self.MAX_FAT32_ITEMS):
                    renamed_path: str = f'{os.path.normpath(path=extract_path)}_{to_ordinal(in_number=suffix)}'

                    if not is_dir(in_path=renamed_path):
                        extract_path = renamed_path

                        break

            if self.parse_format(input_object=input_file, extract_path=extract_path, padding=padding + 8):
                exit_code -= 1

            if is_empty_dir(in_path=extract_path):
                delete_dirs(in_path=extract_path)

        printer(message='Done!\n' if not self.arguments.auto_exit else None, pause=not self.arguments.auto_exit)

        return exit_code == 0

    def show_version(self, is_boxed: bool = True, padding: int = 0) -> None:
        """ Show title and version of utility """

        printer(message=to_boxed(in_text=self.title) if is_boxed else self.title, new_line=False, padding=padding)

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool:
        """ Process input object as a specific supported format """

        raise NotImplementedError(f'Method "parse_format" not implemented at {__name__}')

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input object is of specific supported format """

        raise NotImplementedError(f'Method "check_format" not implemented at {__name__}')

    def _setup_input_files(self, padding: int = 0) -> None:
        self._input_files = []

        input_paths: list[str] = self.arguments.paths

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

        output_path: str = self.arguments.output_dir

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
