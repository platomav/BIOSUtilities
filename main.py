#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2018-2024 Plato Mavropoulos
"""

from argparse import ArgumentParser, Namespace
from pathlib import Path

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


if __name__ == '__main__':
    main_argparser: ArgumentParser = ArgumentParser(allow_abbrev=False)

    main_argparser.add_argument('input_files', nargs='+')
    main_argparser.add_argument('--output-folder', help='extraction folder')
    main_argparser.add_argument('--pause-exit', help='pause on exit', action='store_false')

    main_arguments: Namespace = main_argparser.parse_args()

    if main_arguments.output_folder:
        output_folder: Path = Path(main_arguments.output_folder)
    else:
        output_folder = Path(main_arguments.input_files[0]).parent

    util_arguments: list[str] = [*main_arguments.input_files, '-e', '-o', str(output_folder.absolute())]

    AmiUcpExtract(arguments=util_arguments).run_utility()
    AmiPfatExtract(arguments=util_arguments).run_utility()
    InsydeIfdExtract(arguments=util_arguments).run_utility()
    DellPfsExtract(arguments=util_arguments).run_utility()
    PhoenixTdkExtract(arguments=util_arguments).run_utility()
    PanasonicBiosExtract(arguments=util_arguments).run_utility()
    VaioPackageExtract(arguments=util_arguments).run_utility()
    PortwellEfiExtract(arguments=util_arguments).run_utility()
    ToshibaComExtract(arguments=util_arguments).run_utility()
    FujitsuSfxExtract(arguments=util_arguments).run_utility()
    FujitsuUpcExtract(arguments=util_arguments).run_utility()
    AwardBiosExtract(arguments=util_arguments).run_utility()
    AppleEfiPkgExtract(arguments=util_arguments).run_utility()
    AppleEfiPbzxExtract(arguments=util_arguments).run_utility()
    AppleEfiIm4pSplit(arguments=util_arguments).run_utility()
    AppleEfiIdentify(arguments=util_arguments).run_utility()

    if main_arguments.pause_exit:
        input('Press any key to exit...')
