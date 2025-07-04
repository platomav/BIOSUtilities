#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2025 Plato Mavropoulos
"""

import re

from typing import Final

PAT_AMI_PFAT: Final[re.Pattern[bytes]] = re.compile(
    br'_AMIPFAT.AMI_BIOS_GUARD_FLASH_CONFIGURATIONS',
    flags=re.DOTALL
)

PAT_AMI_UCP: Final[re.Pattern[bytes]] = re.compile(
    br'@(UAF|HPU).{12}@',
    flags=re.DOTALL
)

PAT_APPLE_ROM_VER: Final[re.Pattern[bytes]] = re.compile(
    br'Apple ROM Version\x0A\x20{2}'
)

PAT_APPLE_IM4P: Final[re.Pattern[bytes]] = re.compile(
    br'\x16\x04IM4P\x16\x04mefi'
)

PAT_APPLE_PBZX: Final[re.Pattern[bytes]] = re.compile(
    br'pbzx'
)

PAT_AWARD_LZH: Final[re.Pattern[bytes]] = re.compile(
    br'-lh[04567]-'
)

PAT_DELL_FTR: Final[re.Pattern[bytes]] = re.compile(
    br'\xEE\xAA\xEE\x8F\x49\x1B\xE8\xAE\x14\x37\x90'
)

PAT_DELL_HDR: Final[re.Pattern[bytes]] = re.compile(
    br'\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78\x9C',
    flags=re.DOTALL
)

PAT_DELL_PKG: Final[re.Pattern[bytes]] = re.compile(
    br'\x13\x55\x00.{45}7zXZ',
    flags=re.DOTALL
)

PAT_FUJITSU_SFX: Final[re.Pattern[bytes]] = re.compile(
    br'FjSfxBinay\xB2\xAC\xBC\xB9\xFF{4}.{4}\xFF{4}.{4}\xFF{4}\xFC\xFE',
    flags=re.DOTALL
)

PAT_INSYDE_IFL: Final[re.Pattern[bytes]] = re.compile(
    br'\$_IFLASH'
)

PAT_INSYDE_SFX: Final[re.Pattern[bytes]] = re.compile(
    br'\x0D\x0A;!@InstallEnd@!\x0D\x0A(7z\xBC\xAF\x27|\x6E\xF4\x79\x5F\x4E)'
)

PAT_INTEL_ENGINE: Final[re.Pattern[bytes]] = re.compile(
    br'\x04\x00{3}[\xA1\xE1]\x00{3}.{8}\x86\x80.{9}\x00\$((MN2)|(MAN))',
    flags=re.DOTALL
)

PAT_INTEL_FD: Final[re.Pattern[bytes]] = re.compile(
    br'\x5A\xA5\xF0\x0F.{172}\xFF{16}',
    flags=re.DOTALL
)

PAT_INTEL_IBIOSI: Final[re.Pattern[bytes]] = re.compile(
    br'\$IBIOSI\$.{16}\x2E\x00.{6}\x2E\x00.{8}\x2E\x00.{6}\x2E\x00.{20}\x00{2}',
    flags=re.DOTALL
)

PAT_MICROSOFT_CAB: Final[re.Pattern[bytes]] = re.compile(
    br'MSCF\x00{4}'
)

PAT_MICROSOFT_MZ: Final[re.Pattern[bytes]] = re.compile(
    br'MZ'
)

PAT_MICROSOFT_PE: Final[re.Pattern[bytes]] = re.compile(
    br'PE\x00{2}'
)

PAT_PHOENIX_TDK: Final[re.Pattern[bytes]] = re.compile(
    br'\$PACK\x00{3}..\x00{2}.\x00{3}',
    flags=re.DOTALL
)

PAT_PORTWELL_EFI: Final[re.Pattern[bytes]] = re.compile(
    br'<U{2}>'
)

PAT_TOSHIBA_COM: Final[re.Pattern[bytes]] = re.compile(
    br'\x00{2}[\x00-\x02]BIOS.{20}[\x00\x01]',
    flags=re.DOTALL
)

PAT_VAIO_CAB: Final[re.Pattern[bytes]] = re.compile(
    br'\xB2\xAC\xBC\xB9\xFF{4}.{4}\xFF{4}.{4}\xFF{4}\xFC\xFE',
    flags=re.DOTALL
)

PAT_VAIO_CFG: Final[re.Pattern[bytes]] = re.compile(
    br'\[Setting]\x0D\x0A'
)

PAT_VAIO_CHK: Final[re.Pattern[bytes]] = re.compile(
    br'\x0AUseVAIOCheck='
)

PAT_VAIO_EXT: Final[re.Pattern[bytes]] = re.compile(
    br'\x0AExtractPathByUser='
)
