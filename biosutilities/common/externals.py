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


def big_script_tool() -> Type | None:
    """ Get Intel BIOS Guard Script Tool class """

    bgst: str | None = shutil.which(cmd='big_script_tool')

    if bgst and os.path.isfile(path=bgst):
        bgst_spec: ModuleSpec | None = spec_from_file_location(
            name='big_script_tool', location=re.sub(r'\.PY$', '.py', bgst))

        if bgst_spec and isinstance(bgst_spec.loader, Loader):
            bgst_module: ModuleType | None = module_from_spec(spec=bgst_spec)

            if bgst_module:
                sys.modules['big_script_tool'] = bgst_module

                bgst_spec.loader.exec_module(module=bgst_module)

                return getattr(bgst_module, 'BigScript')

    return None


def comextract_path() -> str:
    """ Get ToshibaComExtractor path """

    comextract: str | None = shutil.which(cmd='comextract')

    if not (comextract and os.path.isfile(path=comextract)):
        raise OSError('comextract executable not found!')

    return comextract


def szip_path() -> str:
    """ Get 7-Zip path """

    szip: str | None = shutil.which(cmd='7zzs') or shutil.which(cmd='7z')

    if not (szip and os.path.isfile(path=szip)):
        raise OSError('7zzs or 7z executable not found!')

    return szip


def tiano_path() -> str:
    """ Get TianoCompress path """

    tiano: str | None = shutil.which(cmd='TianoCompress')

    if not (tiano and os.path.isfile(path=tiano)):
        raise OSError('TianoCompress executable not found!')

    return tiano


def uefifind_path() -> str:
    """ Get UEFIFind path """

    uefifind: str | None = shutil.which(cmd='UEFIFind')

    if not (uefifind and os.path.isfile(path=uefifind)):
        raise OSError('UEFIFind executable not found!')

    return uefifind


def uefiextract_path() -> str:
    """ Get UEFIExtract path """

    uefiextract: str | None = shutil.which(cmd='UEFIExtract')

    if not (uefiextract and os.path.isfile(path=uefiextract)):
        raise OSError('UEFIExtract executable not found!')

    return uefiextract
