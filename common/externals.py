#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

from common.path_ops import project_root, safe_path
from common.system import get_os_ver


def get_bgs_tool():
    """
    https://github.com/allowitsme/big-tool by Dmitry Frolov
    https://github.com/platomav/BGScriptTool by Plato Mavropoulos
    """

    try:
        # noinspection PyUnresolvedReferences
        from external.big_script_tool import BigScript  # pylint: disable=C0415

        return BigScript
    except ModuleNotFoundError:
        pass

    return None


def get_comextract_path() -> str:
    """ Get ToshibaComExtractor path """

    exec_name = f'comextract{".exe" if get_os_ver()[1] else ""}'

    return safe_path(project_root(), ['external', exec_name])


def get_szip_path() -> str:
    """ Get 7-Zip path """

    exec_name = '7z.exe' if get_os_ver()[1] else '7zzs'

    return safe_path(project_root(), ['external', exec_name])


def get_tiano_path() -> str:
    """ Get TianoCompress path """

    exec_name = f'TianoCompress{".exe" if get_os_ver()[1] else ""}'

    return safe_path(project_root(), ['external', exec_name])


def get_uefifind_path() -> str:
    """ Get UEFIFind path """

    exec_name = f'UEFIFind{".exe" if get_os_ver()[1] else ""}'

    return safe_path(project_root(), ['external', exec_name])


def get_uefiextract_path() -> str:
    """ Get UEFIExtract path """

    exec_name = f'UEFIExtract{".exe" if get_os_ver()[1] else ""}'

    return safe_path(project_root(), ['external', exec_name])
