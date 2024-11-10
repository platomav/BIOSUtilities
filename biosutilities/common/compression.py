#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import subprocess

from typing import Final

from biosutilities.common.externals import szip_path, tiano_path
from biosutilities.common.paths import is_dir, is_file_read, is_empty_dir, path_size
from biosutilities.common.system import printer
from biosutilities.common.texts import file_to_bytes

# 7-Zip switches to auto rename, ignore passwords, ignore prompts, ignore wildcards,
# eliminate root duplication, set UTF-8 charset, suppress stdout, suppress stderr,
# suppress progress, disable headers, disable progress, disable output logging
SZIP_COMMON: Final[list[str]] = ['-aou', '-p', '-y', '-spd', '-spe', '-sccUTF-8',
                                 '-bso0', '-bse0', '-bsp0', '-ba', '-bd', '-bb0']

# Success exit codes (0 = OK, 1 = Warnings)
SZIP_SUCCESS: Final[list[int]] = [0, 1]


def szip_switches(in_switches: list[str]) -> list[str]:
    """ Generate 7-Zip command line switches """

    common_switches: list[str] = SZIP_COMMON

    for in_switch in in_switches:
        for sw_pattern in ('-p', '-ao', '-bs', '-bb', '-scc'):
            if in_switch.startswith(sw_pattern):
                common_switches = [sw for sw in common_switches if not sw.startswith(sw_pattern)]

                break

    return [*set(common_switches + in_switches), '--']


def is_szip_successful(exit_code: int) -> bool:
    """ Check 7-Zip success exit codes """

    if exit_code in SZIP_SUCCESS:
        return True

    return False


def is_szip_supported(in_path: str, args: list | None = None) -> bool:
    """ Check if file is 7-Zip supported """

    szip_a: list[str] = [] if args is None else args

    szip_c: list[str] = [szip_path(), 't', *szip_switches(in_switches=[*szip_a]), in_path]

    szip_t: subprocess.CompletedProcess[bytes] = subprocess.run(szip_c, check=False, stdout=subprocess.DEVNULL)

    return is_szip_successful(exit_code=szip_t.returncode)


def szip_decompress(in_path: str, out_path: str, in_name: str = 'archive', padding: int = 0, args: list | None = None,
                    check: bool = False, silent: bool = False) -> bool:
    """ Archive decompression via 7-Zip """

    szip_a: list[str] = [] if args is None else args

    szip_c: list[str] = [szip_path(), 'x', *szip_switches(in_switches=[*szip_a, f'-o{out_path}']), in_path]

    szip_x: subprocess.CompletedProcess[bytes] = subprocess.run(szip_c, check=False, stdout=subprocess.DEVNULL)

    szip_s: bool = is_szip_successful(exit_code=szip_x.returncode) if check else True

    if szip_s and is_dir(in_path=out_path) and not is_empty_dir(in_path=out_path):
        if not silent:
            printer(message=f'Successful {in_name} decompression via 7-Zip!', padding=padding)

        return True

    return False


def efi_header_info(in_object: str | bytes | bytearray) -> dict[str, int]:
    """ Get EFI compression sizes from header """

    efi_data: bytes = file_to_bytes(in_object=in_object)

    size_compressed: int = int.from_bytes(efi_data[0x0:0x4], byteorder='little')

    size_decompressed: int = int.from_bytes(efi_data[0x4:0x8], byteorder='little')

    return {'size_compressed': size_compressed, 'size_decompressed': size_decompressed}


def is_efi_compressed(in_object: str | bytes | bytearray, strict: bool = True) -> bool:
    """ Check if data is EFI compressed, controlling EOF padding """

    efi_data: bytes = file_to_bytes(in_object=in_object)

    efi_sizes: dict[str, int] = efi_header_info(in_object=efi_data)

    check_diff: bool = efi_sizes['size_compressed'] < efi_sizes['size_decompressed']

    if strict:
        check_size: bool = efi_sizes['size_compressed'] + 0x8 == len(efi_data)
    else:
        check_size = efi_sizes['size_compressed'] + 0x8 <= len(efi_data)

    return check_diff and check_size


def efi_decompress(in_path: str, out_path: str, padding: int = 0, silent: bool = False,
                   comp_type: str = '--uefi') -> bool:
    """ EFI/Tiano Decompression via TianoCompress """

    tiano_c: list[str] = [tiano_path(), '-d', in_path, '-o', out_path, '-q', comp_type]

    tiano_x: subprocess.CompletedProcess[bytes] = subprocess.run(tiano_c, check=False, stdout=subprocess.DEVNULL)

    if tiano_x.returncode == 0 and is_file_read(in_path=out_path):
        if efi_header_info(in_object=in_path)['size_decompressed'] == path_size(in_path=out_path):
            if not silent:
                printer(message='Successful EFI decompression via TianoCompress!', padding=padding)

            return True

    return False
