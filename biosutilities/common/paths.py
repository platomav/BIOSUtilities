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
from typing import Callable, Final

from biosutilities.common.system import system_platform
from biosutilities.common.texts import to_string

MAX_WIN_COMP_LEN: Final[int] = 255


def safe_name(in_name: str) -> str:
    """
    Fix illegal/reserved Windows characters
    Can also be used to nuke dangerous paths
    """

    name_repr: str = repr(in_name).strip("'")

    return re.sub(pattern=r'[\\/:"*?<>|]+', repl='_', string=name_repr)


def safe_path(base_path: str, user_paths: str | list | tuple) -> str:
    """ Check and attempt to fix illegal/unsafe OS path traversals """

    # Convert base path to absolute path
    base_path = real_path(in_path=base_path)

    # Merge user path(s) to string with OS separators
    user_path: str = to_string(in_object=user_paths, sep_char=os.sep)

    # Create target path from base + requested user path
    target_path: str = norm_path(base_path=base_path, user_path=user_path)

    # Check if target path is OS illegal/unsafe
    if is_safe_path(base_path=base_path, target_path=target_path):
        return target_path

    # Re-create target path from base + leveled/safe illegal "path" (now file)
    nuked_path: str = norm_path(base_path=base_path, user_path=safe_name(in_name=user_path))

    # Check if illegal path leveling worked
    if is_safe_path(base_path=base_path, target_path=nuked_path):
        return nuked_path

    # Still illegal, raise exception to halt execution
    raise OSError(f'Encountered illegal path traversal: {user_path}')


def is_safe_path(base_path: str, target_path: str) -> bool:
    """ Check for illegal/unsafe OS path traversal """

    base_path = real_path(in_path=base_path)

    target_path = real_path(in_path=target_path)

    common_path: str = os.path.commonpath(paths=(base_path, target_path))

    return base_path == common_path


def norm_path(base_path: str, user_path: str) -> str:
    """ Create normalized base path + OS separator + user path """

    return os.path.normpath(path=base_path + os.sep + user_path)


def real_path(in_path: str) -> str:
    """ Get absolute path, resolving any symlinks """

    return os.path.realpath(in_path)


def agnostic_path(in_path: str) -> PurePath:
    """ Get Windows/Posix OS-agnostic path """

    return PurePath(in_path.replace('\\', os.sep))


def path_parent(in_path: str) -> Path:
    """ Get absolute parent of path """

    return Path(in_path).parent.absolute()


def path_name(in_path: str, limit: bool = False) -> str:
    """ Get final path component, with suffix """

    comp_name: str = PurePath(in_path).name

    is_win: bool = system_platform()[1]

    if limit and is_win:
        comp_name = comp_name[:MAX_WIN_COMP_LEN - len(extract_suffix())]

    return comp_name


def path_stem(in_path: str) -> str:
    """ Get final path component, w/o suffix """

    return PurePath(in_path).stem


def path_suffixes(in_path: str) -> list[str]:
    """ Get list of path file extensions """

    return PurePath(in_path).suffixes or ['']


def make_dirs(in_path: str, parents: bool = True, exist_ok: bool = False, delete: bool = False):
    """ Create folder(s), controlling parents, existence and prior deletion """

    if delete:
        delete_dirs(in_path=in_path)

    Path.mkdir(Path(in_path), parents=parents, exist_ok=exist_ok)


def delete_dirs(in_path: str) -> None:
    """ Delete folder(s), if present """

    if is_dir(in_path=in_path):
        shutil.rmtree(path=in_path, onerror=clear_readonly_callback)  # pylint: disable=deprecated-argument


def delete_file(in_path: str) -> None:
    """ Delete file, if present """

    if Path(in_path).is_file():
        clear_readonly(in_path=in_path)

        os.remove(path=in_path)


def copy_file(in_path: str, out_path: str, metadata: bool = False) -> None:
    """ Copy file to path with or w/o metadata """

    if metadata:
        shutil.copy2(src=in_path, dst=out_path)
    else:
        shutil.copy(src=in_path, dst=out_path)


def clear_readonly(in_path: str) -> None:
    """ Clear read-only file attribute """

    os.chmod(path=in_path, mode=stat.S_IWRITE)


def clear_readonly_callback(in_func: Callable, in_path: str, _) -> None:
    """ Clear read-only file attribute (on shutil.rmtree error) """

    clear_readonly(in_path=in_path)

    in_func(path=in_path)


def path_files(in_path: str, follow_links: bool = False, root_only: bool = False) -> list[str]:
    """ Walk path to get all files """

    file_paths: list[str] = []

    for root_path, _, file_names in os.walk(top=in_path, followlinks=follow_links):
        for file_name in file_names:
            file_path: str = os.path.abspath(path=os.path.join(root_path, file_name))

            if is_file(in_path=file_path):
                file_paths.append(file_path)

        if root_only:
            break

    return file_paths


def is_dir(in_path: str) -> bool:
    """ Check if path is a directory """

    return Path(in_path).is_dir()


def is_file(in_path: str, allow_broken_links: bool = False) -> bool:
    """ Check if path is a regural file or symlink (valid or broken) """

    in_path_abs: str = os.path.abspath(path=in_path)

    if os.path.lexists(path=in_path_abs):
        if not is_dir(in_path=in_path_abs):
            if allow_broken_links:
                return os.path.isfile(path=in_path_abs) or os.path.islink(path=in_path_abs)

            return os.path.isfile(path=in_path_abs)

    return False


def is_access(in_path: str, access_mode: int = os.R_OK, follow_links: bool = False) -> bool:
    """ Check if path is accessible """

    if not follow_links and os.access not in os.supports_follow_symlinks:
        follow_links = True

    return os.access(path=in_path, mode=access_mode, follow_symlinks=follow_links)


def is_empty_dir(in_path: str, follow_links: bool = False) -> bool:
    """ Check if directory is empty (file-wise) """

    for _, _, filenames in os.walk(top=in_path, followlinks=follow_links):
        if filenames:
            return False

    return True


def extract_suffix() -> str:
    """ Set utility extraction stem """

    return '_extracted'


def extract_folder(in_path: str, suffix: str = extract_suffix()) -> str:
    """ Get utility extraction directory """

    return f'{in_path}{suffix}'


def project_root() -> str:
    """ Get project root directory """

    return real_path(in_path=str(Path(__file__).parent.parent))


def runtime_root() -> str:
    """ Get runtime root directory """

    if getattr(sys, 'frozen', False):
        root: str = str(Path(sys.executable).parent)
    else:
        root = project_root()

    return real_path(in_path=root)
