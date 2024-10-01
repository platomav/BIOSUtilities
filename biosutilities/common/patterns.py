#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""

import re

from typing import Final

PAT_AMI_PFAT: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'_AMIPFAT.AMI_BIOS_GUARD_FLASH_CONFIGURATIONS',
    flags=re.DOTALL
)

PAT_AMI_UCP: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'@(UAF|HPU).{12}@',
    flags=re.DOTALL
)

PAT_APPLE_EFI: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\$IBIOSI\$.{16}\x2E\x00.{6}\x2E\x00.{8}\x2E\x00.{6}\x2E\x00.{20}\x00{2}',
    flags=re.DOTALL
)

PAT_APPLE_IM4P: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\x16\x04IM4P\x16\x04mefi'
)

PAT_APPLE_PBZX: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'pbzx'
)

PAT_APPLE_PKG_XAR: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'xar!'
)

PAT_APPLE_PKG_TAR: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'<key>IFPkgDescriptionDescription</key>'
)

PAT_AWARD_LZH: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'-lh[04567]-'
)

PAT_DELL_FTR: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\xEE\xAA\xEE\x8F\x49\x1B\xE8\xAE\x14\x37\x90'
)

PAT_DELL_HDR: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78\x9C',
    flags=re.DOTALL
)

PAT_DELL_PKG: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\x72\x13\x55\x00.{45}7zXZ',
    flags=re.DOTALL
)

PAT_FUJITSU_SFX: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'FjSfxBinay\xB2\xAC\xBC\xB9\xFF{4}.{4}\xFF{4}.{4}\xFF{4}\xFC\xFE',
    flags=re.DOTALL
)

PAT_INSYDE_IFL: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\$_IFLASH'
)

PAT_INSYDE_SFX: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\x0D\x0A;!@InstallEnd@!\x0D\x0A(7z\xBC\xAF\x27|\x6E\xF4\x79\x5F\x4E)'
)

PAT_INTEL_ENG: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\x04\x00{3}[\xA1\xE1]\x00{3}.{8}\x86\x80.{9}\x00\$((MN2)|(MAN))',
    flags=re.DOTALL
)

PAT_INTEL_IFD: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\x5A\xA5\xF0\x0F.{172}\xFF{16}',
    flags=re.DOTALL
)

PAT_MICROSOFT_CAB: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'MSCF\x00{4}'
)

PAT_MICROSOFT_MZ: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'MZ'
)

PAT_MICROSOFT_PE: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'PE\x00{2}'
)

PAT_PHOENIX_TDK: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\$PACK\x00{3}..\x00{2}.\x00{3}',
    flags=re.DOTALL
)

PAT_PORTWELL_EFI: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'<U{2}>'
)

PAT_TOSHIBA_COM: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\x00{2}[\x00-\x02]BIOS.{20}[\x00\x01]',
    flags=re.DOTALL
)

PAT_VAIO_CAB: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\xB2\xAC\xBC\xB9\xFF{4}.{4}\xFF{4}.{4}\xFF{4}\xFC\xFE',
    flags=re.DOTALL
)

PAT_VAIO_CFG: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\[Setting]\x0D\x0A'
)

PAT_VAIO_CHK: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\x0AUseVAIOCheck='
)

PAT_VAIO_EXT: Final[re.Pattern[bytes]] = re.compile(
    pattern=br'\x0AExtractPathByUser='
)
