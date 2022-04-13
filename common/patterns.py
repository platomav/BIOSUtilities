#!/usr/bin/env python3
#coding=utf-8

import re

PAT_AMI_PFAT = re.compile(b'_AMIPFAT.AMI_BIOS_GUARD_FLASH_CONFIGURATIONS', re.DOTALL)
PAT_AMI_UCP = re.compile(br'@(UAF|HPU).{12}@', re.DOTALL)
PAT_DELL_PKG = re.compile(br'\x72\x13\x55\x00.{45}7zXZ', re.DOTALL)
PAT_DELL_HDR = re.compile(br'\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78\x9C', re.DOTALL)
PAT_DELL_FTR = re.compile(br'\xEE\xAA\xEE\x8F\x49\x1B\xE8\xAE\x14\x37\x90')
PAT_INTEL_ENG = re.compile(br'\x04\x00{3}[\xA1\xE1]\x00{3}.{8}\x86\x80.{9}\x00\$((MN2)|(MAN))', re.DOTALL)