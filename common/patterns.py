#!/usr/bin/env python3
#coding=utf-8

import re

PAT_AMI_PFAT = re.compile(b'_AMIPFAT.AMI_BIOS_GUARD_FLASH_CONFIGURATIONS', re.DOTALL)
PAT_AMI_UCP = re.compile(br'\x40\x55\x41\x46.{12}\x40', re.DOTALL)
PAT_INTEL_ENG = re.compile(br'\x04\x00{3}[\xA1\xE1]\x00{3}.{8}\x86\x80.{9}\x00\$((MN2)|(MAN))', re.DOTALL)