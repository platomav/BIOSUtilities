#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import os
import re
import shutil
import sys

from importlib.abc import Loader
from importlib.machinery import ModuleSpec
from importlib.util import module_from_spec, spec_from_file_location
from types import ModuleType
from typing import Type

from biosutilities.common.paths import project_root
from biosutilities.common.texts import to_string


def get_external_path(cmd: str | list | tuple, raise_on_error: bool = True) -> str | None:
    """ Get external dependency path (PATH environment variable or "external" directory) """

    external_root: str = os.path.join(project_root(), 'external')

    external_path: str | None = external_root if os.path.isdir(external_root) else None

    for command in cmd if isinstance(cmd, (list, tuple)) else [to_string(in_object=cmd)]:
        command_path: str | None = shutil.which(cmd=command, path=external_path)

        if command_path and os.path.isfile(path=command_path):
            return command_path

    if raise_on_error:
        raise OSError(f'{to_string(in_object=cmd, sep_char=", ")} could not be found!')

    return None


def big_script_tool() -> Type | None:
    """ Get Intel BIOS Guard Script Tool class """

    bgst: str | None = get_external_path(cmd='big_script_tool', raise_on_error=False)

    if bgst is not None:
        bgst_spec: ModuleSpec | None = spec_from_file_location(
            name='big_script_tool', location=re.sub(r'\.PY$', '.py', bgst))

        if bgst_spec and isinstance(bgst_spec.loader, Loader):
            bgst_module: ModuleType | None = module_from_spec(spec=bgst_spec)

            if bgst_module:
                sys.modules['big_script_tool'] = bgst_module

                bgst_spec.loader.exec_module(module=bgst_module)

                return getattr(bgst_module, 'BigScript')

    return None


def comextract_path() -> str | None:
    """ Get ToshibaComExtractor path """

    return get_external_path(cmd='comextract')


def szip_path() -> str | None:
    """ Get 7-Zip path """

    return get_external_path(cmd=['7zzs', '7zz', '7z'])


def tiano_path() -> str | None:
    """ Get TianoCompress path """

    return get_external_path(cmd='TianoCompress')


def uefifind_path() -> str | None:
    """ Get UEFIFind path """

    return get_external_path(cmd='UEFIFind')


def uefiextract_path() -> str | None:
    """ Get UEFIExtract path """

    return get_external_path(cmd='UEFIExtract')
