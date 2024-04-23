#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import os
import re
import shutil
import stat
import sys

from pathlib import Path, PurePath

from common.system import get_os_ver
from common.text_ops import is_encased, to_string

MAX_WIN_COMP_LEN = 255


def safe_name(in_name):
    """
    Fix illegal/reserved Windows characters
    Can also be used to nuke dangerous paths
    """

    name_repr = repr(in_name).strip("'")

    return re.sub(r'[\\/:"*?<>|]+', '_', name_repr)


def safe_path(base_path, user_paths):
    """ Check and attempt to fix illegal/unsafe OS path traversals """

    # Convert base path to absolute path
    base_path = real_path(base_path)

    # Merge user path(s) to string with OS separators
    user_path = to_string(user_paths, os.sep)

    # Create target path from base + requested user path
    target_path = norm_path(base_path, user_path)

    # Check if target path is OS illegal/unsafe
    if is_safe_path(base_path, target_path):
        return target_path

    # Re-create target path from base + leveled/safe illegal "path" (now file)
    nuked_path = norm_path(base_path, safe_name(user_path))

    # Check if illegal path leveling worked
    if is_safe_path(base_path, nuked_path):
        return nuked_path

    # Still illegal, raise exception to halt execution
    raise OSError(f'Encountered illegal path traversal: {user_path}')


def is_safe_path(base_path, target_path):
    """ Check for illegal/unsafe OS path traversal """

    base_path = real_path(base_path)

    target_path = real_path(target_path)

    common_path = os.path.commonpath((base_path, target_path))

    return base_path == common_path


def norm_path(base_path, user_path):
    """ Create normalized base path + OS separator + user path """

    return os.path.normpath(base_path + os.sep + user_path)


def real_path(in_path):
    """ Get absolute path, resolving any symlinks """

    return os.path.realpath(in_path)


def agnostic_path(in_path):
    """ Get Windows/Posix OS agnostic path """

    return PurePath(in_path.replace('\\', os.sep))


def path_parent(in_path):
    """ Get absolute parent of path """

    return Path(in_path).parent.absolute()


def path_name(in_path, limit=False):
    """ Get final path component, with suffix """

    comp_name = PurePath(in_path).name

    if limit and get_os_ver()[1]:
        comp_name = comp_name[:MAX_WIN_COMP_LEN - len(extract_suffix())]

    return comp_name


def path_stem(in_path):
    """ Get final path component, w/o suffix """

    return PurePath(in_path).stem


def path_suffixes(in_path):
    """ Get list of path file extensions """

    return PurePath(in_path).suffixes or ['']


def is_path_absolute(in_path):
    """ Check if path is absolute """

    return Path(in_path).is_absolute()


def make_dirs(in_path, parents=True, exist_ok=False, delete=False):
    """ Create folder(s), controlling parents, existence and prior deletion """

    if delete:
        del_dirs(in_path)

    Path.mkdir(Path(in_path), parents=parents, exist_ok=exist_ok)


def del_dirs(in_path):
    """ Delete folder(s), if present """

    if Path(in_path).is_dir():
        shutil.rmtree(in_path, onerror=clear_readonly_callback)


def copy_file(in_path, out_path, meta=False):
    """ Copy file to path with or w/o metadata """

    if meta:
        shutil.copy2(in_path, out_path)
    else:
        shutil.copy(in_path, out_path)


def clear_readonly(in_path):
    """ Clear read-only file attribute """

    os.chmod(in_path, stat.S_IWRITE)


def clear_readonly_callback(in_func, in_path, _):
    """ Clear read-only file attribute (on shutil.rmtree error) """

    clear_readonly(in_path)

    in_func(in_path)


def get_path_files(in_path):
    """ Walk path to get all files """

    path_files = []

    for root, _, files in os.walk(in_path):
        for name in files:
            path_files.append(os.path.join(root, name))

    return path_files


def get_dequoted_path(in_path):
    """ Get path without leading/trailing quotes """

    out_path = to_string(in_path).strip()

    if len(out_path) >= 2 and is_encased(out_path, ("'", '"')):
        out_path = out_path[1:-1]

    return out_path


def extract_suffix():
    """ Set utility extraction stem """

    return '_extracted'


def get_extract_path(in_path, suffix=extract_suffix()):
    """ Get utility extraction path """

    return f'{in_path}{suffix}'


def project_root():
    """ Get project's root directory """

    return real_path(Path(__file__).parent.parent)


def runtime_root():
    """ Get runtime's root directory """

    if getattr(sys, 'frozen', False):
        root = Path(sys.executable).parent
    else:
        root = project_root()

    return real_path(root)
