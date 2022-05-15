#!/usr/bin/env python3
#coding=utf-8

"""
AMI UCP Extract
AMI UCP BIOS Extractor
Copyright (C) 2021-2022 Plato Mavropoulos
"""

TITLE = 'AMI UCP BIOS Extractor v2.0_a12'

import os
import re
import sys
import struct
import ctypes
import contextlib

# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.a7z_comp import a7z_decompress, is_7z_supported
from common.checksums import get_chk_16
from common.efi_comp import efi_decompress, is_efi_compressed
from common.path_ops import agnostic_path, safe_name, safe_path, make_dirs
from common.patterns import PAT_AMI_UCP, PAT_INTEL_ENG
from common.struct_ops import get_struct, char, uint8_t, uint16_t, uint32_t
from common.system import script_init, argparse_init, printer
from common.text_ops import file_to_bytes, to_string

from AMI_PFAT_Extract import get_ami_pfat, parse_pfat_file

class UafHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('ModuleTag',       char*4),        # 0x00
        ('ModuleSize',      uint32_t),      # 0x04
        ('Checksum',        uint16_t),      # 0x08
        ('Unknown0',        uint8_t),       # 0x0A
        ('Unknown1',        uint8_t),       # 0x0A
        ('Reserved',        uint8_t*4),     # 0x0C
        # 0x10
    ]
    
    def _get_reserved(self):
        res_bytes = bytes(self.Reserved)
        
        res_str = re.sub(r'[\n\t\r\x00 ]', '', res_bytes.decode('utf-8','ignore'))
        
        res_hex = '0x%0.*X' % (0x4 * 2, int.from_bytes(res_bytes, 'big'))
        
        res_out = res_hex + (' (%s)' % res_str if len(res_str) else '')
        
        return res_out
    
    def struct_print(self, p):
        printer(['Tag          :', self.ModuleTag.decode('utf-8')], p, False)
        printer(['Size         :', '0x%X' % self.ModuleSize], p, False)
        printer(['Checksum     :', '0x%0.4X' % self.Checksum], p, False)
        printer(['Unknown 0    :', '0x%0.2X' % self.Unknown0], p, False)
        printer(['Unknown 1    :', '0x%0.2X' % self.Unknown1], p, False)
        printer(['Reserved     :', self._get_reserved()], p, False)

class UafModule(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('CompressSize',    uint32_t),      # 0x00
        ('OriginalSize',    uint32_t),      # 0x04
        # 0x08
    ]
    
    def struct_print(self, p, filename, description):
        printer(['Compress Size:', '0x%X' % self.CompressSize], p, False)
        printer(['Original Size:', '0x%X' % self.OriginalSize], p, False)
        printer(['Filename     :', filename], p, False)
        printer(['Description  :', description], p, False)

class UiiHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('UIISize',         uint16_t),      # 0x00
        ('Checksum',        uint16_t),      # 0x02
        ('UtilityVersion',  uint32_t),      # 0x04 AFU|BGT (Unknown, Signed)
        ('InfoSize',        uint16_t),      # 0x08
        ('SupportBIOS',     uint8_t),       # 0x0A
        ('SupportOS',       uint8_t),       # 0x0B
        ('DataBusWidth',    uint8_t),       # 0x0C
        ('ProgramType',     uint8_t),       # 0x0D
        ('ProgramMode',     uint8_t),       # 0x0E
        ('SourceSafeRel',   uint8_t),       # 0x0F
        # 0x10
    ]
    
    SBI = {1: 'ALL', 2: 'AMIBIOS8', 3: 'UEFI', 4: 'AMIBIOS8/UEFI'}
    SOS = {1: 'DOS', 2: 'EFI', 3: 'Windows', 4: 'Linux', 5: 'FreeBSD', 6: 'MacOS', 128: 'Multi-Platform'}
    DBW = {1: '16b', 2: '16/32b', 3: '32b', 4: '64b'}
    PTP = {1: 'Executable', 2: 'Library', 3: 'Driver'}
    PMD = {1: 'API', 2: 'Console', 3: 'GUI', 4: 'Console/GUI'}
    
    def struct_print(self, p, description):
        SupportBIOS = self.SBI.get(self.SupportBIOS, 'Unknown (%d)' % self.SupportBIOS)
        SupportOS = self.SOS.get(self.SupportOS, 'Unknown (%d)' % self.SupportOS)
        DataBusWidth = self.DBW.get(self.DataBusWidth, 'Unknown (%d)' % self.DataBusWidth)
        ProgramType = self.PTP.get(self.ProgramType, 'Unknown (%d)' % self.ProgramType)
        ProgramMode = self.PMD.get(self.ProgramMode, 'Unknown (%d)' % self.ProgramMode)
        
        printer(['UII Size      :', '0x%X' % self.UIISize], p, False)
        printer(['Checksum      :', '0x%0.4X' % self.Checksum], p, False)
        printer(['Tool Version  :', '0x%0.8X' % self.UtilityVersion], p, False)
        printer(['Info Size     :', '0x%X' % self.InfoSize], p, False)
        printer(['Supported BIOS:', SupportBIOS], p, False)
        printer(['Supported OS  :', SupportOS], p, False)
        printer(['Data Bus Width:', DataBusWidth], p, False)
        printer(['Program Type  :', ProgramType], p, False)
        printer(['Program Mode  :', ProgramMode], p, False)
        printer(['SourceSafe Tag:', '%0.2d' % self.SourceSafeRel], p, False)
        printer(['Description   :', description], p, False)

class DisHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('PasswordSize',    uint16_t),      # 0x00
        ('EntryCount',      uint16_t),      # 0x02
        ('Password',        char*12),       # 0x04
        # 0x10
    ]
    
    def struct_print(self, p):
        printer(['Password Size:', '0x%X' % self.PasswordSize], p, False)
        printer(['Entry Count  :', self.EntryCount], p, False)
        printer(['Password     :', self.Password.decode('utf-8')], p, False)

class DisModule(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('EnabledDisabled', uint8_t),       # 0x00
        ('ShownHidden',     uint8_t),       # 0x01
        ('Command',         char*32),       # 0x02
        ('Description',     char*256),      # 0x22
        # 0x122
    ]
    
    ENDIS = {0: 'Disabled', 1: 'Enabled'}
    SHOWN = {0: 'Hidden', 1: 'Shown', 2: 'Shown Only'}
    
    def struct_print(self, p):
        EnabledDisabled = self.ENDIS.get(self.EnabledDisabled, 'Unknown (%d)' % self.EnabledDisabled)
        ShownHidden = self.SHOWN.get(self.ShownHidden, 'Unknown (%d)' % self.ShownHidden)
        
        printer(['State      :', EnabledDisabled], p, False)
        printer(['Display    :', ShownHidden], p, False)
        printer(['Command    :', self.Command.decode('utf-8').strip()], p, False)
        printer(['Description:', self.Description.decode('utf-8').strip()], p, False)

# Validate UCP Module Checksum-16
def chk16_validate(data, tag, padd=0):
    if get_chk_16(data) != 0:
        printer('Error: Invalid UCP Module %s Checksum!' % tag, padd, pause=True)
    else:
        printer('Checksum of UCP Module %s is valid!' % tag, padd)

# Check if input is AMI UCP image
def is_ami_ucp(in_file):
    buffer = file_to_bytes(in_file)
    
    return bool(get_ami_ucp(buffer)[0])

# Get all input file AMI UCP patterns
def get_ami_ucp(buffer):
    uaf_len_max = 0x0 # Length of largest detected @UAF|@HPU
    uaf_hdr_off = 0x0 # Offset of largest detected @UAF|@HPU
    uaf_buf_bin = b'' # Buffer of largest detected @UAF|@HPU
    uaf_buf_tag = '@UAF' # Tag of largest detected @UAF|@HPU
    
    for uaf in PAT_AMI_UCP.finditer(buffer):
        uaf_len_cur = int.from_bytes(buffer[uaf.start() + 0x4:uaf.start() + 0x8], 'little')
        
        if uaf_len_cur > uaf_len_max:
            uaf_len_max = uaf_len_cur
            uaf_hdr_off = uaf.start()
            uaf_buf_bin = buffer[uaf_hdr_off:uaf_hdr_off + uaf_len_max]
            uaf_buf_tag = uaf.group(0)[:4].decode('utf-8','ignore')
    
    return uaf_hdr_off, uaf_buf_bin, uaf_buf_tag

# Get list of @UAF|@HPU Modules
def get_uaf_mod(buffer, uaf_off=0x0):
    uaf_all = [] # Initialize list of all @UAF|@HPU Modules
    
    while buffer[uaf_off] == 0x40: # ASCII of @ is 0x40
        uaf_hdr = get_struct(buffer, uaf_off, UafHeader) # Parse @UAF|@HPU Module Structure
        
        uaf_tag = uaf_hdr.ModuleTag.decode('utf-8') # Get unique @UAF|@HPU Module Tag
        
        uaf_all.append([uaf_tag, uaf_off, uaf_hdr]) # Store @UAF|@HPU Module Info
        
        uaf_off += uaf_hdr.ModuleSize # Adjust to next @UAF|@HPU Module offset
        
        if uaf_off >= len(buffer): break # Stop parsing at EOF
    
    # Check if @UAF|@HPU Module @NAL exists and place it first
    # Parsing @NAL first allows naming all @UAF|@HPU Modules
    for mod_idx,mod_val in enumerate(uaf_all):
        if mod_val[0] == '@NAL':
            uaf_all.insert(1, uaf_all.pop(mod_idx)) # After UII for visual purposes
            break # @NAL found, skip the rest
    
    return uaf_all

# Parse & Extract AMI UCP structures
def ucp_extract(buffer, out_path, ucp_tag='@UAF', padding=0, is_checksum=False, is_static=False):
    nal_dict = {} # Initialize @NAL Dictionary per UCP
    
    printer('Utility Configuration Program', padding)
    
    extract_path = os.path.join(out_path + '_extracted')
    
    make_dirs(extract_path, delete=True)
    
    uaf_hdr = get_struct(buffer, 0, UafHeader) # Parse @UAF|@HPU Header Structure
    
    printer('Utility Auxiliary File > %s:\n' % ucp_tag, padding + 4)
    
    uaf_hdr.struct_print(padding + 8)
    
    fake = struct.pack('<II', len(buffer), len(buffer)) # Generate UafModule Structure
    
    uaf_mod = get_struct(fake, 0x0, UafModule) # Parse @UAF|@HPU Module EFI Structure
    
    uaf_name = UAF_TAG_DICT[ucp_tag][0] # Get @UAF|@HPU Module Filename
    uaf_desc = UAF_TAG_DICT[ucp_tag][1] # Get @UAF|@HPU Module Description
    
    uaf_mod.struct_print(padding + 8, uaf_name, uaf_desc) # Print @UAF|@HPU Module EFI Info
    
    if is_checksum: chk16_validate(buffer, ucp_tag, padding + 8)
    
    uaf_all = get_uaf_mod(buffer, UAF_HDR_LEN)
    
    for mod_info in uaf_all:
        nal_dict = uaf_extract(buffer, extract_path, mod_info, padding + 8, is_checksum, is_static, nal_dict)

# Parse & Extract AMI UCP > @UAF|@HPU Module/Section
def uaf_extract(buffer, extract_path, mod_info, padding=0, is_checksum=False, is_static=False, nal_dict=None):
    if nal_dict is None: nal_dict = {}
    
    uaf_tag,uaf_off,uaf_hdr = mod_info
    
    uaf_data_all = buffer[uaf_off:uaf_off + uaf_hdr.ModuleSize] # @UAF|@HPU Module Entire Data
    
    uaf_data_mod = uaf_data_all[UAF_HDR_LEN:] # @UAF|@HPU Module EFI Data
    
    uaf_data_raw = uaf_data_mod[UAF_MOD_LEN:] # @UAF|@HPU Module Raw Data
    
    printer('Utility Auxiliary File > %s:\n' % uaf_tag, padding)
    
    uaf_hdr.struct_print(padding + 4) # Print @UAF|@HPU Module Info
    
    uaf_mod = get_struct(buffer, uaf_off + UAF_HDR_LEN, UafModule) # Parse UAF Module EFI Structure
    
    is_comp = uaf_mod.CompressSize != uaf_mod.OriginalSize # Detect @UAF|@HPU Module EFI Compression
    
    if uaf_tag in nal_dict: uaf_name = nal_dict[uaf_tag][1] # Always prefer @NAL naming first
    elif uaf_tag in UAF_TAG_DICT: uaf_name = UAF_TAG_DICT[uaf_tag][0] # Otherwise use built-in naming
    elif uaf_tag == '@ROM': uaf_name = 'BIOS.bin' # BIOS/PFAT Firmware (w/o Signature)
    elif uaf_tag.startswith('@R0'): uaf_name = 'BIOS_0%s.bin' % uaf_tag[3:] # BIOS/PFAT Firmware
    elif uaf_tag.startswith('@S0'): uaf_name = 'BIOS_0%s.sig' % uaf_tag[3:] # BIOS/PFAT Signature
    elif uaf_tag.startswith('@DR'): uaf_name = 'DROM_0%s.bin' % uaf_tag[3:] # Thunderbolt Retimer Firmware
    elif uaf_tag.startswith('@DS'): uaf_name = 'DROM_0%s.sig' % uaf_tag[3:] # Thunderbolt Retimer Signature
    elif uaf_tag.startswith('@EC'): uaf_name = 'EC_0%s.bin' % uaf_tag[3:] # Embedded Controller Firmware
    elif uaf_tag.startswith('@ME'): uaf_name = 'ME_0%s.bin' % uaf_tag[3:] # Management Engine Firmware
    else: uaf_name = uaf_tag # Could not name the @UAF|@HPU Module, use Tag instead
    
    uaf_fext = '' if uaf_name != uaf_tag else '.bin'
    
    uaf_fdesc = UAF_TAG_DICT[uaf_tag][1] if uaf_tag in UAF_TAG_DICT else uaf_name
    
    uaf_mod.struct_print(padding + 4, uaf_name + uaf_fext, uaf_fdesc) # Print @UAF|@HPU Module EFI Info
    
    # Check if unknown @UAF|@HPU Module Tag is present in @NAL but not in built-in dictionary
    if uaf_tag in nal_dict and uaf_tag not in UAF_TAG_DICT and not uaf_tag.startswith(('@ROM','@R0','@S0','@DR','@DS')):
        printer('Note: Detected new AMI UCP Module %s (%s) in @NAL!' % (uaf_tag, nal_dict[uaf_tag][1]), padding + 4, pause=True)
    
    # Generate @UAF|@HPU Module File name, depending on whether decompression will be required
    uaf_sname = safe_name(uaf_name + ('.temp' if is_comp else uaf_fext))
    if uaf_tag in nal_dict:
        uaf_npath = safe_path(extract_path, nal_dict[uaf_tag][0])
        make_dirs(uaf_npath, exist_ok=True)
        uaf_fname = safe_path(uaf_npath, uaf_sname)
    else:
        uaf_fname = safe_path(extract_path, uaf_sname)
    
    if is_checksum: chk16_validate(uaf_data_all, uaf_tag, padding + 4)
    
    # Parse Utility Identification Information @UAF|@HPU Module (@UII)
    if uaf_tag == '@UII':
        info_hdr = get_struct(uaf_data_raw, 0, UiiHeader) # Parse @UII Module Raw Structure
        
        info_data = uaf_data_raw[max(UII_HDR_LEN,info_hdr.InfoSize):info_hdr.UIISize] # @UII Module Info Data
        
        # Get @UII Module Info/Description text field
        info_desc = info_data.decode('utf-8','ignore').strip('\x00 ')
        
        printer('Utility Identification Information:\n', padding + 4)
        
        info_hdr.struct_print(padding + 8, info_desc) # Print @UII Module Info
        
        if is_checksum: chk16_validate(uaf_data_raw, '@UII > Info', padding + 8)
        
        # Store/Save @UII Module Info in file
        with open(uaf_fname[:-4] + '.txt', 'a', encoding='utf-8') as uii_out:
            with contextlib.redirect_stdout(uii_out):
                info_hdr.struct_print(0, info_desc) # Store @UII Module Info
    
    # Adjust @UAF|@HPU Module Raw Data for extraction
    if is_comp:
        # Some Compressed @UAF|@HPU Module EFI data lack necessary EOF padding
        if uaf_mod.CompressSize > len(uaf_data_raw):
            comp_padd = b'\x00' * (uaf_mod.CompressSize - len(uaf_data_raw))
            uaf_data_raw = uaf_data_mod[:UAF_MOD_LEN] + uaf_data_raw + comp_padd # Add missing padding for decompression
        else:
            uaf_data_raw = uaf_data_mod[:UAF_MOD_LEN] + uaf_data_raw # Add the EFI/Tiano Compression info before Raw Data
    else:
        uaf_data_raw = uaf_data_raw[:uaf_mod.OriginalSize] # No compression, extend to end of Original @UAF|@HPU Module size
    
    # Store/Save @UAF|@HPU Module file
    if uaf_tag != '@UII': # Skip @UII binary, already parsed
        with open(uaf_fname, 'wb') as uaf_out: uaf_out.write(uaf_data_raw)
    
    # @UAF|@HPU Module EFI/Tiano Decompression
    if is_comp and is_efi_compressed(uaf_data_raw, False):
        dec_fname = uaf_fname.replace('.temp', uaf_fext) # Decompressed @UAF|@HPU Module file path
        
        if efi_decompress(uaf_fname, dec_fname, padding + 4) == 0:
            with open(dec_fname, 'rb') as dec: uaf_data_raw = dec.read() # Read back the @UAF|@HPU Module decompressed Raw data
            
            os.remove(uaf_fname) # Successful decompression, delete compressed @UAF|@HPU Module file
            
            uaf_fname = dec_fname # Adjust @UAF|@HPU Module file path to the decompressed one
    
    # Process and Print known text only @UAF|@HPU Modules (after EFI/Tiano Decompression)
    if uaf_tag in UAF_TAG_DICT and UAF_TAG_DICT[uaf_tag][2] == 'Text':
        printer(UAF_TAG_DICT[uaf_tag][1] + ':', padding + 4)
        printer(uaf_data_raw.decode('utf-8','ignore'), padding + 8)
    
    # Parse Default Command Status @UAF|@HPU Module (@DIS)
    if len(uaf_data_raw) and uaf_tag == '@DIS':
        dis_hdr = get_struct(uaf_data_raw, 0x0, DisHeader) # Parse @DIS Module Raw Header Structure
        
        printer('Default Command Status Header:\n', padding + 4)
        
        dis_hdr.struct_print(padding + 8) # Print @DIS Module Raw Header Info
        
        # Store/Save @DIS Module Header Info in file
        with open(uaf_fname[:-3] + 'txt', 'a', encoding='utf-8') as dis:
            with contextlib.redirect_stdout(dis):
                dis_hdr.struct_print(0) # Store @DIS Module Header Info
        
        dis_data = uaf_data_raw[DIS_HDR_LEN:] # @DIS Module Entries Data
        
        # Parse all @DIS Module Entries
        for mod_idx in range(dis_hdr.EntryCount):
            dis_mod = get_struct(dis_data, mod_idx * DIS_MOD_LEN, DisModule) # Parse @DIS Module Raw Entry Structure
            
            printer('Default Command Status Entry %0.2d/%0.2d:\n' % (mod_idx + 1, dis_hdr.EntryCount), padding + 8)
            
            dis_mod.struct_print(padding + 12) # Print @DIS Module Raw Entry Info
            
            # Store/Save @DIS Module Entry Info in file
            with open(uaf_fname[:-3] + 'txt', 'a', encoding='utf-8') as dis:
                with contextlib.redirect_stdout(dis):
                    printer()
                    dis_mod.struct_print(4) # Store @DIS Module Entry Info
        
        os.remove(uaf_fname) # Delete @DIS Module binary, info exported as text
    
    # Parse Name List @UAF|@HPU Module (@NAL)
    if len(uaf_data_raw) >= 5 and (uaf_tag,uaf_data_raw[0],uaf_data_raw[4]) == ('@NAL',0x40,0x3A):
        nal_info = uaf_data_raw.decode('utf-8','ignore').replace('\r','').strip().split('\n')
        
        printer('AMI UCP Module Name List:\n', padding + 4)
        
        # Parse all @NAL Module Entries
        for info in nal_info:
            info_tag,info_value = info.split(':',1)
            
            printer(info_tag + ' : ' + info_value, padding + 8, False) # Print @NAL Module Tag-Path Info
            
            info_part = agnostic_path(info_value).parts # Split OS agnostic path in parts
            info_path = to_string(info_part[1:-1], os.sep) # Get path without drive/root or file
            info_name = info_part[-1] # Get file from last path part
            
            nal_dict[info_tag] = (info_path,info_name) # Assign a file path & name to each Tag
    
    # Parse Insyde BIOS @UAF|@HPU Module (@INS)
    if uaf_tag == '@INS' and is_7z_supported(uaf_fname, padding + 4, static=is_static):
        ins_dir = os.path.join(extract_path, safe_name(uaf_tag + '_nested-SFX')) # Generate extraction directory
        
        printer('Insyde BIOS 7z SFX Archive:', padding + 4)
        
        if a7z_decompress(uaf_fname, ins_dir, '7z SFX', padding + 8, static=is_static) == 0:
            os.remove(uaf_fname) # Successful extraction, delete @INS Module file/archive
    
    # Detect & Unpack AMI BIOS Guard (PFAT) BIOS image
    pfat_match,pfat_buffer = get_ami_pfat(uaf_data_raw)
    
    if pfat_match:
        pfat_dir = os.path.join(extract_path, safe_name(uaf_name))
        
        parse_pfat_file(pfat_buffer, pfat_dir, padding + 4)
        
        os.remove(uaf_fname) # Delete PFAT Module file after extraction
    
    # Detect Intel Engine firmware image and show ME Analyzer advice
    if uaf_tag.startswith('@ME') and PAT_INTEL_ENG.search(uaf_data_raw):
        printer('Intel Management Engine (ME) Firmware:\n', padding + 4)
        printer('Use "ME Analyzer" from https://github.com/platomav/MEAnalyzer', padding + 8, False)
    
    # Get best Nested AMI UCP Pattern match based on @UAF|@HPU Size
    nested_uaf_off,nested_uaf_bin,nested_uaf_tag = get_ami_ucp(uaf_data_raw)
    
    # Parse Nested AMI UCP Structure
    if nested_uaf_off:
        uaf_dir = os.path.join(extract_path, safe_name(uaf_tag + '_nested-UCP')) # Generate extraction directory
        
        ucp_extract(nested_uaf_bin, uaf_dir, nested_uaf_tag, padding + 4, is_checksum, is_static) # Call recursively
        
        os.remove(uaf_fname) # Delete raw nested AMI UCP Structure after successful recursion/extraction
    
    return nal_dict

# Get common ctypes Structure Sizes
UAF_HDR_LEN = ctypes.sizeof(UafHeader)
UAF_MOD_LEN = ctypes.sizeof(UafModule)
DIS_HDR_LEN = ctypes.sizeof(DisHeader)
DIS_MOD_LEN = ctypes.sizeof(DisModule)
UII_HDR_LEN = ctypes.sizeof(UiiHeader)

# AMI UCP Tag Dictionary
UAF_TAG_DICT = {
    '@3FI' : ['HpBiosUpdate32.efi', 'HpBiosUpdate32.efi', ''],
    '@3S2' : ['HpBiosUpdate32.s12', 'HpBiosUpdate32.s12', ''],
    '@3S4' : ['HpBiosUpdate32.s14', 'HpBiosUpdate32.s14', ''],
    '@3S9' : ['HpBiosUpdate32.s09', 'HpBiosUpdate32.s09', ''],
    '@3SG' : ['HpBiosUpdate32.sig', 'HpBiosUpdate32.sig', ''],
    '@AMI' : ['UCP_Nested.bin', 'Nested AMI UCP', ''],
    '@B12' : ['BiosMgmt.s12', 'BiosMgmt.s12', ''],
    '@B14' : ['BiosMgmt.s14', 'BiosMgmt.s14', ''],
    '@B32' : ['BiosMgmt32.s12', 'BiosMgmt32.s12', ''],
    '@B34' : ['BiosMgmt32.s14', 'BiosMgmt32.s14', ''],
    '@B39' : ['BiosMgmt32.s09', 'BiosMgmt32.s09', ''],
    '@B3E' : ['BiosMgmt32.efi', 'BiosMgmt32.efi', ''],
    '@BM9' : ['BiosMgmt.s09', 'BiosMgmt.s09', ''],
    '@BME' : ['BiosMgmt.efi', 'BiosMgmt.efi', ''],
    '@CKV' : ['Check_Version.txt', 'Check Version', 'Text'],
    '@CMD' : ['AFU_Command.txt', 'AMI AFU Command', 'Text'],
    '@CPM' : ['AC_Message.txt', 'Confirm Power Message', ''],
    '@DCT' : ['DevCon32.exe', 'Device Console WIN32', ''],
    '@DCX' : ['DevCon64.exe', 'Device Console WIN64', ''],
    '@DFE' : ['HpDevFwUpdate.efi', 'HpDevFwUpdate.efi', ''],
    '@DFS' : ['HpDevFwUpdate.s12', 'HpDevFwUpdate.s12', ''],
    '@DIS' : ['Command_Status.bin', 'Default Command Status', ''],
    '@ENB' : ['ENBG64.exe', 'ENBG64.exe', ''],
    '@HPU' : ['UCP_Main.bin', 'Utility Auxiliary File (HP)', ''],
    '@INS' : ['Insyde_Nested.bin', 'Nested Insyde SFX', ''],
    '@M32' : ['HpBiosMgmt32.s12', 'HpBiosMgmt32.s12', ''],
    '@M34' : ['HpBiosMgmt32.s14', 'HpBiosMgmt32.s14', ''],
    '@M39' : ['HpBiosMgmt32.s09', 'HpBiosMgmt32.s09', ''],
    '@M3I' : ['HpBiosMgmt32.efi', 'HpBiosMgmt32.efi', ''],
    '@MEC' : ['FWUpdLcl.txt', 'Intel FWUpdLcl Command', 'Text'],
    '@MED' : ['FWUpdLcl_DOS.exe', 'Intel FWUpdLcl DOS', ''],
    '@MET' : ['FWUpdLcl_WIN32.exe', 'Intel FWUpdLcl WIN32', ''],
    '@MFI' : ['HpBiosMgmt.efi', 'HpBiosMgmt.efi', ''],
    '@MS2' : ['HpBiosMgmt.s12', 'HpBiosMgmt.s12', ''],
    '@MS4' : ['HpBiosMgmt.s14', 'HpBiosMgmt.s14', ''],
    '@MS9' : ['HpBiosMgmt.s09', 'HpBiosMgmt.s09', ''],
    '@NAL' : ['UCP_List.txt', 'AMI UCP Module Name List', ''],
    '@OKM' : ['OK_Message.txt', 'OK Message', ''],
    '@PFC' : ['BGT_Command.txt', 'AMI BGT Command', 'Text'],
    '@R3I' : ['CryptRSA32.efi', 'CryptRSA32.efi', ''],
    '@RFI' : ['CryptRSA.efi', 'CryptRSA.efi', ''],
    '@UAF' : ['UCP_Main.bin', 'Utility Auxiliary File (AMI)', ''],
    '@UFI' : ['HpBiosUpdate.efi', 'HpBiosUpdate.efi', ''],
    '@UII' : ['UCP_Info.txt', 'Utility Identification Information', ''],
    '@US2' : ['HpBiosUpdate.s12', 'HpBiosUpdate.s12', ''],
    '@US4' : ['HpBiosUpdate.s14', 'HpBiosUpdate.s14', ''],
    '@US9' : ['HpBiosUpdate.s09', 'HpBiosUpdate.s09', ''],
    '@USG' : ['HpBiosUpdate.sig', 'HpBiosUpdate.sig', ''],
    '@VER' : ['OEM_Version.txt', 'OEM Version', 'Text'],
    '@VXD' : ['amifldrv.vxd', 'amifldrv.vxd', ''],
    '@W32' : ['amifldrv32.sys', 'amifldrv32.sys', ''],
    '@W64' : ['amifldrv64.sys', 'amifldrv64.sys', ''],
    }

if __name__ == '__main__':
    # Set argparse Arguments    
    argparser = argparse_init()
    argparser.add_argument('-c', '--checksum', help='verify AMI UCP Checksums (slow)', action='store_true')
    arguments = argparser.parse_args()
    
    is_checksum = arguments.checksum # Set Checksum verification optional argument
    is_static = arguments.static # Set Static dependencies usage optional argument
    
    # Initialize script (must be after argparse)
    exit_code,input_files,output_path,padding = script_init(TITLE, arguments, 4)
    
    for input_file in input_files:
        input_name = os.path.basename(input_file)
        
        printer(['***', input_name], padding - 4)
        
        with open(input_file, 'rb') as in_file: input_buffer = in_file.read()
        
        # Get best AMI UCP Pattern match based on @UAF|@HPU Size
        main_uaf_off,main_uaf_bin,main_uaf_tag = get_ami_ucp(input_buffer)
        
        if not main_uaf_off:
            printer('Error: This is not an AMI UCP BIOS executable!', padding)
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        ucp_extract(main_uaf_bin, extract_path, main_uaf_tag, padding, is_checksum, is_static)
        
        exit_code -= 1
    
    printer('Done!', pause=True)
    
    sys.exit(exit_code)
