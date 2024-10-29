#!/usr/bin/env python3 -B
# coding=utf-8

"""
AMI UCP Extract
AMI UCP Update Extractor
Copyright (C) 2021-2024 Plato Mavropoulos
"""

import contextlib
import ctypes
import os
import re
import struct

from typing import Any, Final

from biosutilities.common.checksums import checksum_16
from biosutilities.common.compression import efi_decompress, is_efi_compressed
from biosutilities.common.paths import agnostic_path, delete_file, extract_folder, make_dirs, safe_name, safe_path
from biosutilities.common.patterns import PAT_AMI_UCP, PAT_INTEL_ENGINE
from biosutilities.common.structs import CHAR, ctypes_struct, UINT8, UINT16, UINT32
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import to_string

from biosutilities.ami_pfat_extract import AmiPfatExtract
from biosutilities.insyde_ifd_extract import InsydeIfdExtract


class UafHeader(ctypes.LittleEndianStructure):
    """ UAF Header """

    _pack_ = 1
    _fields_ = [
        ('ModuleTag',       CHAR * 4),      # 0x00
        ('ModuleSize',      UINT32),        # 0x04
        ('Checksum',        UINT16),        # 0x08
        ('Unknown0',        UINT8),         # 0x0A
        ('Unknown1',        UINT8),         # 0x0A
        ('Reserved',        UINT8 * 4)      # 0x0C
        # 0x10
    ]

    def _get_reserved(self) -> str:
        res_bytes: bytes = bytes(self.Reserved)

        res_hex: str = f'0x{int.from_bytes(res_bytes, byteorder="big"):0{0x4 * 2}X}'

        res_str: str = re.sub(r'[\n\t\r\x00 ]', '', res_bytes.decode('utf-8', 'ignore'))

        res_txt: str = f' ({res_str})' if len(res_str) else ''

        return f'{res_hex}{res_txt}'

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Tag          :', self.ModuleTag.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['Size         :', f'0x{self.ModuleSize:X}'], padding=padding, new_line=False)
        printer(message=['Checksum     :', f'0x{self.Checksum:04X}'], padding=padding, new_line=False)
        printer(message=['Unknown 0    :', f'0x{self.Unknown0:02X}'], padding=padding, new_line=False)
        printer(message=['Unknown 1    :', f'0x{self.Unknown1:02X}'], padding=padding, new_line=False)
        printer(message=['Reserved     :', self._get_reserved()], padding=padding, new_line=False)


class UafModule(ctypes.LittleEndianStructure):
    """ UAF Module """

    _pack_ = 1
    _fields_ = [
        ('CompressSize',    UINT32),        # 0x00
        ('OriginalSize',    UINT32)         # 0x04
        # 0x08
    ]

    def struct_print(self, filename: str, description: str, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Compress Size:', f'0x{self.CompressSize:X}'], padding=padding, new_line=False)
        printer(message=['Original Size:', f'0x{self.OriginalSize:X}'], padding=padding, new_line=False)
        printer(message=['Filename     :', filename], padding=padding, new_line=False)
        printer(message=['Description  :', description], padding=padding, new_line=False)


class UiiHeader(ctypes.LittleEndianStructure):
    """ UII Header """

    _pack_ = 1
    _fields_ = [
        ('UIISize',         UINT16),        # 0x00
        ('Checksum',        UINT16),        # 0x02
        ('UtilityVersion',  UINT32),        # 0x04 AFU|BGT (Unknown, Signed)
        ('InfoSize',        UINT16),        # 0x08
        ('SupportBIOS',     UINT8),         # 0x0A
        ('SupportOS',       UINT8),         # 0x0B
        ('DataBusWidth',    UINT8),         # 0x0C
        ('ProgramType',     UINT8),         # 0x0D
        ('ProgramMode',     UINT8),         # 0x0E
        ('SourceSafeRel',   UINT8)          # 0x0F
        # 0x10
    ]

    SBI: Final[dict[int, str]] = {1: 'ALL', 2: 'AMIBIOS8', 3: 'UEFI', 4: 'AMIBIOS8/UEFI'}
    SOS: Final[dict[int, str]] = {1: 'DOS', 2: 'EFI', 3: 'Windows', 4: 'Linux', 5: 'FreeBSD',
                                  6: 'MacOS', 128: 'Multi-Platform'}
    DBW: Final[dict[int, str]] = {1: '16b', 2: '16/32b', 3: '32b', 4: '64b'}
    PTP: Final[dict[int, str]] = {1: 'Executable', 2: 'Library', 3: 'Driver'}
    PMD: Final[dict[int, str]] = {1: 'API', 2: 'Console', 3: 'GUI', 4: 'Console/GUI'}

    def struct_print(self, description: str, padding: int = 0) -> None:
        """ Display structure information """

        support_bios: str = self.SBI.get(self.SupportBIOS, f'Unknown ({self.SupportBIOS})')
        support_os: str = self.SOS.get(self.SupportOS, f'Unknown ({self.SupportOS})')
        data_bus_width: str = self.DBW.get(self.DataBusWidth, f'Unknown ({self.DataBusWidth})')
        program_type: str = self.PTP.get(self.ProgramType, f'Unknown ({self.ProgramType})')
        program_mode: str = self.PMD.get(self.ProgramMode, f'Unknown ({self.ProgramMode})')

        printer(message=['UII Size      :', f'0x{self.UIISize:X}'], padding=padding, new_line=False)
        printer(message=['Checksum      :', f'0x{self.Checksum:04X}'], padding=padding, new_line=False)
        printer(message=['Tool Version  :', f'0x{self.UtilityVersion:08X}'], padding=padding, new_line=False)
        printer(message=['Info Size     :', f'0x{self.InfoSize:X}'], padding=padding, new_line=False)
        printer(message=['Supported BIOS:', support_bios], padding=padding, new_line=False)
        printer(message=['Supported OS  :', support_os], padding=padding, new_line=False)
        printer(message=['Data Bus Width:', data_bus_width], padding=padding, new_line=False)
        printer(message=['Program Type  :', program_type], padding=padding, new_line=False)
        printer(message=['Program Mode  :', program_mode], padding=padding, new_line=False)
        printer(message=['SourceSafe Tag:', f'{self.SourceSafeRel:02d}'], padding=padding, new_line=False)
        printer(message=['Description   :', description], padding=padding, new_line=False)


class DisHeader(ctypes.LittleEndianStructure):
    """ DIS Header """

    _pack_ = 1
    _fields_ = [
        ('PasswordSize',    UINT16),        # 0x00
        ('EntryCount',      UINT16),        # 0x02
        ('Password',        CHAR * 12)      # 0x04
        # 0x10
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Password Size:', f'0x{self.PasswordSize:X}'], padding=padding, new_line=False)
        printer(message=['Entry Count  :', self.EntryCount], padding=padding, new_line=False)
        printer(message=['Password     :', self.Password.decode('utf-8')], padding=padding, new_line=False)


class DisModule(ctypes.LittleEndianStructure):
    """ DIS Module """

    _pack_ = 1
    _fields_ = [
        ('EnabledDisabled', UINT8),         # 0x00
        ('ShownHidden',     UINT8),         # 0x01
        ('Command',         CHAR * 32),     # 0x02
        ('Description',     CHAR * 256)     # 0x22
        # 0x122
    ]

    ENDIS: Final[dict[int, str]] = {0: 'Disabled', 1: 'Enabled'}
    SHOWN: Final[dict[int, str]] = {0: 'Hidden', 1: 'Shown', 2: 'Shown Only'}

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        enabled_disabled: str = self.ENDIS.get(self.EnabledDisabled, f'Unknown ({self.EnabledDisabled})')
        shown_hidden: str = self.SHOWN.get(self.ShownHidden, f'Unknown ({self.ShownHidden})')
        command: str = self.Command.decode('utf-8').strip()
        description: str = self.Description.decode('utf-8').strip()

        printer(message=['State      :', enabled_disabled], padding=padding, new_line=False)
        printer(message=['Display    :', shown_hidden], padding=padding, new_line=False)
        printer(message=['Command    :', command], padding=padding, new_line=False)
        printer(message=['Description:', description], padding=padding, new_line=False)


class AmiUcpExtract(BIOSUtility):
    """ AMI UCP Update Extractor """

    TITLE: str = 'AMI UCP Update Extractor'

    # Get common ctypes Structure Sizes
    UAF_HDR_LEN: Final[int] = ctypes.sizeof(UafHeader)
    UAF_MOD_LEN: Final[int] = ctypes.sizeof(UafModule)
    DIS_HDR_LEN: Final[int] = ctypes.sizeof(DisHeader)
    DIS_MOD_LEN: Final[int] = ctypes.sizeof(DisModule)
    UII_HDR_LEN: Final[int] = ctypes.sizeof(UiiHeader)

    # AMI UCP Tag Dictionary
    UAF_TAG_DICT: Final[dict[str, list[str]]] = {
        '@3FI': ['HpBiosUpdate32.efi', 'HpBiosUpdate32.efi', ''],
        '@3S2': ['HpBiosUpdate32.s12', 'HpBiosUpdate32.s12', ''],
        '@3S4': ['HpBiosUpdate32.s14', 'HpBiosUpdate32.s14', ''],
        '@3S9': ['HpBiosUpdate32.s09', 'HpBiosUpdate32.s09', ''],
        '@3SG': ['HpBiosUpdate32.sig', 'HpBiosUpdate32.sig', ''],
        '@AMI': ['UCP_Nested.bin', 'Nested AMI UCP', ''],
        '@B12': ['BiosMgmt.s12', 'BiosMgmt.s12', ''],
        '@B14': ['BiosMgmt.s14', 'BiosMgmt.s14', ''],
        '@B32': ['BiosMgmt32.s12', 'BiosMgmt32.s12', ''],
        '@B34': ['BiosMgmt32.s14', 'BiosMgmt32.s14', ''],
        '@B39': ['BiosMgmt32.s09', 'BiosMgmt32.s09', ''],
        '@B3E': ['BiosMgmt32.efi', 'BiosMgmt32.efi', ''],
        '@BM9': ['BiosMgmt.s09', 'BiosMgmt.s09', ''],
        '@BME': ['BiosMgmt.efi', 'BiosMgmt.efi', ''],
        '@CKV': ['Check_Version.txt', 'Check Version', 'Text'],
        '@CMD': ['AFU_Command.txt', 'AMI AFU Command', 'Text'],
        '@CML': ['CMOSD4.txt', 'CMOS Item Number-Value (MSI)', 'Text'],
        '@CMS': ['CMOSD4.exe', 'Get or Set CMOS Item (MSI)', ''],
        '@CPM': ['AC_Message.txt', 'Confirm Power Message', ''],
        '@D32': ['amifldrv32.sys', 'amifldrv32.sys', ''],
        '@D64': ['amifldrv64.sys', 'amifldrv64.sys', ''],
        '@DCT': ['DevCon32.exe', 'Device Console WIN32', ''],
        '@DCX': ['DevCon64.exe', 'Device Console WIN64', ''],
        '@DFE': ['HpDevFwUpdate.efi', 'HpDevFwUpdate.efi', ''],
        '@DFS': ['HpDevFwUpdate.s12', 'HpDevFwUpdate.s12', ''],
        '@DIS': ['Command_Status.bin', 'Default Command Status', ''],
        '@ENB': ['ENBG64.exe', 'ENBG64.exe', ''],
        '@HPU': ['UCP_Main.bin', 'Utility Auxiliary File (HP)', ''],
        '@INS': ['Insyde_Nested.bin', 'Nested Insyde SFX', ''],
        '@M32': ['HpBiosMgmt32.s12', 'HpBiosMgmt32.s12', ''],
        '@M34': ['HpBiosMgmt32.s14', 'HpBiosMgmt32.s14', ''],
        '@M39': ['HpBiosMgmt32.s09', 'HpBiosMgmt32.s09', ''],
        '@M3I': ['HpBiosMgmt32.efi', 'HpBiosMgmt32.efi', ''],
        '@MEC': ['FWUpdLcl.txt', 'Intel FWUpdLcl Command', 'Text'],
        '@MED': ['FWUpdLcl_DOS.exe', 'Intel FWUpdLcl DOS', ''],
        '@MET': ['FWUpdLcl_WIN32.exe', 'Intel FWUpdLcl WIN32', ''],
        '@MFI': ['HpBiosMgmt.efi', 'HpBiosMgmt.efi', ''],
        '@MS2': ['HpBiosMgmt.s12', 'HpBiosMgmt.s12', ''],
        '@MS4': ['HpBiosMgmt.s14', 'HpBiosMgmt.s14', ''],
        '@MS9': ['HpBiosMgmt.s09', 'HpBiosMgmt.s09', ''],
        '@NAL': ['UCP_List.txt', 'AMI UCP Module Name List', ''],
        '@OKM': ['OK_Message.txt', 'OK Message', ''],
        '@PFC': ['BGT_Command.txt', 'AMI BGT Command', 'Text'],
        '@R3I': ['CryptRSA32.efi', 'CryptRSA32.efi', ''],
        '@RFI': ['CryptRSA.efi', 'CryptRSA.efi', ''],
        '@UAF': ['UCP_Main.bin', 'Utility Auxiliary File (AMI)', ''],
        '@UFI': ['HpBiosUpdate.efi', 'HpBiosUpdate.efi', ''],
        '@UII': ['UCP_Info.txt', 'Utility Identification Information', ''],
        '@US2': ['HpBiosUpdate.s12', 'HpBiosUpdate.s12', ''],
        '@US4': ['HpBiosUpdate.s14', 'HpBiosUpdate.s14', ''],
        '@US9': ['HpBiosUpdate.s09', 'HpBiosUpdate.s09', ''],
        '@USG': ['HpBiosUpdate.sig', 'HpBiosUpdate.sig', ''],
        '@VER': ['OEM_Version.txt', 'OEM Version', 'Text'],
        '@VXD': ['amifldrv.vxd', 'amifldrv.vxd', ''],
        '@W32': ['amifldrv32.sys', 'amifldrv32.sys', ''],
        '@W64': ['amifldrv64.sys', 'amifldrv64.sys', '']
    }

    def __init__(self, input_object: str | bytes | bytearray = b'', extract_path: str = '', padding: int = 0,
                 checksum: bool = False) -> None:
        super().__init__(input_object=input_object, extract_path=extract_path, padding=padding)

        self.checksum: bool = checksum

    def check_format(self) -> bool:
        """ Check if input is AMI UCP image """

        return bool(self._get_ami_ucp()[0])

    def parse_format(self) -> bool:
        """ Parse & Extract AMI UCP structures """

        nal_dict: dict[str, tuple[str, str]] = {}  # Initialize @NAL Dictionary per UCP

        printer(message='Utility Configuration Program', padding=self.padding)

        make_dirs(in_path=self.extract_path)

        # Get best AMI UCP Pattern match based on @UAF|@HPU Size
        ucp_buffer, ucp_tag = self._get_ami_ucp()

        # Parse @UAF|@HPU Header Structure
        uaf_hdr: Any = ctypes_struct(buffer=ucp_buffer, start_offset=0, class_object=UafHeader)

        printer(message=f'Utility Auxiliary File > {ucp_tag}:\n', padding=self.padding + 4)

        uaf_hdr.struct_print(padding=self.padding + 8)

        # Generate UafModule Structure
        fake: bytes = struct.pack('<II', len(ucp_buffer), len(ucp_buffer))

        # Parse @UAF|@HPU Module EFI Structure
        uaf_mod: Any = ctypes_struct(buffer=fake, start_offset=0, class_object=UafModule)

        # Get @UAF|@HPU Module Filename
        uaf_name = self.UAF_TAG_DICT[ucp_tag][0]

        # Get @UAF|@HPU Module Description
        uaf_desc = self.UAF_TAG_DICT[ucp_tag][1]

        # Print @UAF|@HPU Module EFI Info
        uaf_mod.struct_print(filename=uaf_name, description=uaf_desc, padding=self.padding + 8)

        if self.checksum:
            self._chk16_validate(data=ucp_buffer, tag=ucp_tag, padding=self.padding + 8)

        uaf_all = self._get_uaf_mod(buffer=ucp_buffer, uaf_off=self.UAF_HDR_LEN)

        for mod_info in uaf_all:
            nal_dict = self._uaf_extract(buffer=ucp_buffer, extract_path=self.extract_path, mod_info=mod_info,
                                         nal_dict=nal_dict, padding=self.padding + 8)

        return True

    @staticmethod
    def _chk16_validate(data: bytes | bytearray, tag: str, padding: int = 0) -> None:
        """ Validate UCP Module Checksum-16 """

        if checksum_16(data=data) != 0:
            printer(message=f'Error: Invalid UCP Module {tag} Checksum!', padding=padding)
        else:
            printer(message=f'Checksum of UCP Module {tag} is valid!', padding=padding)

    def _get_ami_ucp(self) -> tuple[bytes, str]:
        """ Get all input file AMI UCP patterns """

        uaf_len_max: int = 0x0  # Length of largest detected @UAF|@HPU
        uaf_buf_bin: bytes = b''  # Buffer of largest detected @UAF|@HPU
        uaf_buf_tag: str = '@UAF'  # Tag of largest detected @UAF|@HPU

        for uaf in PAT_AMI_UCP.finditer(self.input_buffer):
            uaf_len_cur: int = int.from_bytes(
                self.input_buffer[uaf.start() + 0x4:uaf.start() + 0x8], byteorder='little')

            if uaf_len_cur > uaf_len_max:
                uaf_len_max = uaf_len_cur

                uaf_buf_bin = self.input_buffer[uaf.start():uaf.start() + uaf_len_max]

                uaf_buf_tag = uaf.group(0)[:4].decode('utf-8', 'ignore')

        return uaf_buf_bin, uaf_buf_tag

    @staticmethod
    def _get_uaf_mod(buffer: bytes | bytearray, uaf_off: int = 0x0) -> list[list]:
        """ Get list of @UAF|@HPU Modules """

        uaf_all: list[list] = []  # Initialize list of all @UAF|@HPU Modules

        while buffer[uaf_off] == 0x40:  # ASCII of @ is 0x40
            # Parse @UAF|@HPU Module Structure
            uaf_hdr: Any = ctypes_struct(buffer=buffer, start_offset=uaf_off, class_object=UafHeader)

            uaf_tag: str = uaf_hdr.ModuleTag.decode('utf-8')  # Get unique @UAF|@HPU Module Tag

            uaf_all.append([uaf_tag, uaf_off, uaf_hdr])  # Store @UAF|@HPU Module Info

            uaf_off += uaf_hdr.ModuleSize  # Adjust to next @UAF|@HPU Module offset

            if uaf_off >= len(buffer):
                break  # Stop parsing at EOF

        # Check if @UAF|@HPU Module @NAL exists and place it first
        # Parsing @NAL first allows naming all @UAF|@HPU Modules
        for mod_idx, mod_val in enumerate(uaf_all):
            if mod_val[0] == '@NAL':
                uaf_all.insert(1, uaf_all.pop(mod_idx))  # After UII for visual purposes

                break  # @NAL found, skip the rest

        return uaf_all

    def _uaf_extract(self, buffer: bytes | bytearray, extract_path: str, mod_info: list,
                     nal_dict: dict[str, tuple[str, str]], padding: int = 0) -> dict[str, tuple[str, str]]:
        """ Parse & Extract AMI UCP > @UAF|@HPU Module/Section """

        uaf_tag: str = mod_info[0]
        uaf_off: int = mod_info[1]
        uaf_hdr: Any = mod_info[2]

        uaf_data_all: bytes = buffer[uaf_off:uaf_off + uaf_hdr.ModuleSize]  # @UAF|@HPU Module Entire Data

        uaf_data_mod: bytes = uaf_data_all[self.UAF_HDR_LEN:]  # @UAF|@HPU Module EFI Data

        uaf_data_raw: bytes = uaf_data_mod[self.UAF_MOD_LEN:]  # @UAF|@HPU Module Raw Data

        printer(message=f'Utility Auxiliary File > {uaf_tag}:\n', padding=padding)

        uaf_hdr.struct_print(padding=padding + 4)  # Print @UAF|@HPU Module Info

        # Parse UAF Module EFI Structure
        uaf_mod: Any = ctypes_struct(buffer=buffer, start_offset=uaf_off + self.UAF_HDR_LEN, class_object=UafModule)

        is_comp: bool = uaf_mod.CompressSize != uaf_mod.OriginalSize  # Detect @UAF|@HPU Module EFI Compression

        if uaf_tag in nal_dict:
            uaf_name: str = nal_dict[uaf_tag][1]  # Always prefer @NAL naming first
        elif uaf_tag in self.UAF_TAG_DICT:
            uaf_name = self.UAF_TAG_DICT[uaf_tag][0]  # Otherwise use built-in naming
        elif uaf_tag == '@ROM':
            uaf_name = 'BIOS.bin'  # BIOS/PFAT Firmware (w/o Signature)
        elif uaf_tag.startswith('@R0'):
            uaf_name = f'BIOS_0{uaf_tag[3:]}.bin'  # BIOS/PFAT Firmware
        elif uaf_tag.startswith('@S0'):
            uaf_name = f'BIOS_0{uaf_tag[3:]}.sig'  # BIOS/PFAT Signature
        elif uaf_tag.startswith('@DR'):
            uaf_name = f'DROM_0{uaf_tag[3:]}.bin'  # Thunderbolt Retimer Firmware
        elif uaf_tag.startswith('@DS'):
            uaf_name = f'DROM_0{uaf_tag[3:]}.sig'  # Thunderbolt Retimer Signature
        elif uaf_tag.startswith('@EC'):
            uaf_name = f'EC_0{uaf_tag[3:]}.bin'  # Embedded Controller Firmware
        elif uaf_tag.startswith('@ME'):
            uaf_name = f'ME_0{uaf_tag[3:]}.bin'  # Management Engine Firmware
        else:
            uaf_name = uaf_tag  # Could not name the @UAF|@HPU Module, use Tag instead

        uaf_fext: str = '' if uaf_name != uaf_tag else '.bin'

        uaf_fdesc: str = self.UAF_TAG_DICT[uaf_tag][1] if uaf_tag in self.UAF_TAG_DICT else uaf_name

        # Print @UAF|@HPU Module EFI Info
        uaf_mod.struct_print(filename=uaf_name + uaf_fext, description=uaf_fdesc, padding=padding + 4)

        # Check if unknown @UAF|@HPU Module Tag is present in @NAL but not in built-in dictionary
        if uaf_tag in nal_dict and uaf_tag not in self.UAF_TAG_DICT and \
                not uaf_tag.startswith(('@ROM', '@R0', '@S0', '@DR', '@DS')):

            printer(message=f'Note: Detected new AMI UCP Module {uaf_tag} ({nal_dict[uaf_tag][1]}) in @NAL!',
                    padding=padding + 4)

        # Generate @UAF|@HPU Module File name, depending on whether decompression will be required
        uaf_sname: str = safe_name(in_name=uaf_name + ('.temp' if is_comp else uaf_fext))

        if uaf_tag in nal_dict:
            uaf_npath: str = safe_path(base_path=extract_path, user_paths=nal_dict[uaf_tag][0])

            make_dirs(in_path=uaf_npath)

            uaf_fname: str = safe_path(base_path=uaf_npath, user_paths=uaf_sname)
        else:
            uaf_fname = safe_path(base_path=extract_path, user_paths=uaf_sname)

        if self.checksum:
            self._chk16_validate(data=uaf_data_all, tag=uaf_tag, padding=padding + 4)

        # Parse Utility Identification Information @UAF|@HPU Module (@UII)
        if uaf_tag == '@UII':
            # Parse @UII Module Raw Structure
            info_hdr: Any = ctypes_struct(buffer=uaf_data_raw, start_offset=0, class_object=UiiHeader)

            # @UII Module Info Data
            info_data: bytes = uaf_data_raw[max(self.UII_HDR_LEN, info_hdr.InfoSize):info_hdr.UIISize]

            # Get @UII Module Info/Description text field
            info_desc: str = info_data.decode('utf-8', 'ignore').strip('\x00 ')

            printer(message='Utility Identification Information:\n', padding=padding + 4)

            info_hdr.struct_print(description=info_desc, padding=padding + 8)  # Print @UII Module Info

            if self.checksum:
                self._chk16_validate(data=uaf_data_raw, tag='@UII > Info', padding=padding + 8)

            # Store/Save @UII Module Info in file
            with open(uaf_fname[:-4] + '.txt', 'a', encoding='utf-8') as uii_out:
                with contextlib.redirect_stdout(uii_out):
                    info_hdr.struct_print(description=info_desc, padding=0)  # Store @UII Module Info

        # Adjust @UAF|@HPU Module Raw Data for extraction
        if is_comp:
            # Some Compressed @UAF|@HPU Module EFI data lack necessary EOF padding
            if uaf_mod.CompressSize > len(uaf_data_raw):
                comp_padd: bytes = b'\x00' * (uaf_mod.CompressSize - len(uaf_data_raw))

                # Add missing padding for decompression
                uaf_data_raw = uaf_data_mod[:self.UAF_MOD_LEN] + uaf_data_raw + comp_padd
            else:
                # Add the EFI/Tiano Compression info before Raw Data
                uaf_data_raw = uaf_data_mod[:self.UAF_MOD_LEN] + uaf_data_raw
        else:
            # No compression, extend to end of Original @UAF|@HPU Module size
            uaf_data_raw = uaf_data_raw[:uaf_mod.OriginalSize]

        # Store/Save @UAF|@HPU Module file
        if uaf_tag != '@UII':  # Skip @UII binary, already parsed
            with open(uaf_fname, 'wb') as uaf_out:
                uaf_out.write(uaf_data_raw)

        # @UAF|@HPU Module EFI/Tiano Decompression
        if is_comp and is_efi_compressed(in_object=uaf_data_raw, strict=False):
            # Decompressed @UAF|@HPU Module file path
            dec_fname: str = uaf_fname.replace('.temp', uaf_fext)

            if efi_decompress(in_path=uaf_fname, out_path=dec_fname, padding=padding + 4):
                with open(dec_fname, 'rb') as dec:
                    uaf_data_raw = dec.read()  # Read back the @UAF|@HPU Module decompressed Raw data

                delete_file(in_path=uaf_fname)  # Successful decompression, delete compressed @UAF|@HPU Module file

                uaf_fname = dec_fname  # Adjust @UAF|@HPU Module file path to the decompressed one

        # Process and Print known text only @UAF|@HPU Modules (after EFI/Tiano Decompression)
        if uaf_tag in self.UAF_TAG_DICT and self.UAF_TAG_DICT[uaf_tag][2] == 'Text':
            printer(message=f'{self.UAF_TAG_DICT[uaf_tag][1]}:', padding=padding + 4)

            printer(message=uaf_data_raw.decode('utf-8', 'ignore'), padding=padding + 8)

        # Parse Default Command Status @UAF|@HPU Module (@DIS)
        if len(uaf_data_raw) and uaf_tag == '@DIS':
            # Parse @DIS Module Raw Header Structure
            dis_hdr: Any = ctypes_struct(buffer=uaf_data_raw, start_offset=0, class_object=DisHeader)

            printer(message='Default Command Status Header:\n', padding=padding + 4)

            dis_hdr.struct_print(padding=padding + 8)  # Print @DIS Module Raw Header Info

            # Store/Save @DIS Module Header Info in file
            with open(uaf_fname[:-3] + 'txt', 'a', encoding='utf-8') as dis:
                with contextlib.redirect_stdout(dis):
                    dis_hdr.struct_print(padding=0)  # Store @DIS Module Header Info

            dis_data: bytes = uaf_data_raw[self.DIS_HDR_LEN:]  # @DIS Module Entries Data

            # Parse all @DIS Module Entries
            for mod_idx in range(dis_hdr.EntryCount):
                # Parse @DIS Module Raw Entry Structure
                dis_mod: Any = ctypes_struct(buffer=dis_data, start_offset=mod_idx * self.DIS_MOD_LEN,
                                             class_object=DisModule)

                printer(message=f'Default Command Status Entry {mod_idx + 1:02d}/{dis_hdr.EntryCount:02d}:\n',
                        padding=padding + 8)

                dis_mod.struct_print(padding=padding + 12)  # Print @DIS Module Raw Entry Info

                # Store/Save @DIS Module Entry Info in file
                with open(uaf_fname[:-3] + 'txt', 'a', encoding='utf-8') as dis:
                    with contextlib.redirect_stdout(dis):
                        printer(message=None)

                        dis_mod.struct_print(padding=4)  # Store @DIS Module Entry Info

            delete_file(in_path=uaf_fname)  # Delete @DIS Module binary, info exported as text

        # Parse Name List @UAF|@HPU Module (@NAL)
        if len(uaf_data_raw) >= 5 and (uaf_tag, uaf_data_raw[0], uaf_data_raw[4]) == ('@NAL', 0x40, 0x3A):
            nal_info: list[str] = uaf_data_raw.decode('utf-8',
                                                      errors='ignore').replace('\r', '').strip().split('\n')

            printer(message='AMI UCP Module Name List:\n', padding=padding + 4)

            # Parse all @NAL Module Entries
            for info in nal_info:
                info_tag, info_value = info.split(':', 1)

                # Print @NAL Module Tag-Path Info
                printer(message=f'{info_tag} : {info_value}', padding=padding + 8, new_line=False)

                # Split OS-agnostic path in parts
                info_part: Any = agnostic_path(in_path=info_value).parts

                # Get path without drive/root or file
                info_path: str = to_string(in_object=info_part[1:-1], sep_char=os.sep)

                # Get file from last path part
                info_name: str = info_part[-1]

                # Assign a file path & name to each Tag
                nal_dict[info_tag] = (info_path, info_name)

        # Parse Insyde BIOS @UAF|@HPU Module (@INS)
        if uaf_tag == '@INS':
            ins_dir: str = os.path.join(extract_path, safe_name(in_name=f'{uaf_tag}_nested-IFD'))

            insyde_ifd_extract: InsydeIfdExtract = InsydeIfdExtract(
                input_object=uaf_fname, extract_path=extract_folder(ins_dir), padding=padding + 4)

            if insyde_ifd_extract.check_format():
                if insyde_ifd_extract.parse_format():
                    delete_file(in_path=uaf_fname)  # Delete raw nested Insyde IFD image after successful extraction

        pfat_dir: str = os.path.join(extract_path, safe_name(in_name=uaf_name))

        ami_pfat_extract: AmiPfatExtract = AmiPfatExtract(
            input_object=uaf_data_raw, extract_path=extract_folder(pfat_dir), padding=padding + 4)

        # Detect & Unpack AMI BIOS Guard (PFAT) BIOS image
        if ami_pfat_extract.check_format():
            ami_pfat_extract.parse_format()

            delete_file(in_path=uaf_fname)  # Delete raw PFAT BIOS image after successful extraction

        # Detect Intel Engine firmware image and show ME Analyzer advice
        if uaf_tag.startswith('@ME') and PAT_INTEL_ENGINE.search(uaf_data_raw):
            printer(message='Intel Management Engine (ME) Firmware:\n', padding=padding + 4)
            printer(message='Use "ME Analyzer" from https://github.com/platomav/MEAnalyzer',
                    padding=padding + 8, new_line=False)

        uaf_dir: str = extract_folder(os.path.join(extract_path, safe_name(in_name=f'{uaf_tag}_nested-UCP')))

        ami_ucp_extract: AmiUcpExtract = AmiUcpExtract(
            input_object=uaf_data_raw, extract_path=uaf_dir, padding=padding + 4, checksum=self.checksum)

        # Parse Nested AMI UCP image
        if ami_ucp_extract.check_format():
            ami_ucp_extract.parse_format()

            delete_file(in_path=uaf_fname)  # Delete raw nested AMI UCP image after successful extraction

        return nal_dict
