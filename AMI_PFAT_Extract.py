#!/usr/bin/env python3
#coding=utf-8

"""
AMI PFAT Extract
AMI BIOS Guard Extractor
Copyright (C) 2018-2022 Plato Mavropoulos
"""

title = 'AMI BIOS Guard Extractor v4.0_a1'

import os
import re
import sys
import shutil
import ctypes

# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.patterns import PAT_AMI_PFAT
from common.externals import get_bgs_tool
from common.num_ops import get_ordinal
from common.text_ops import padder
from common.path_ops import argparse_init, process_input_files, safe_name
from common.struct_ops import get_struct, char, uint8_t, uint16_t, uint32_t
from common.system import nice_exc_handler, check_sys_py, check_sys_os, show_title, print_input

class AmiBiosGuardHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('Size',            uint32_t),      # 0x00 Header + Entries
        ('Checksum',        uint32_t),      # 0x04 ?
        ('Tag',             char*8),        # 0x04 _AMIPFAT
        ('Flags',           uint8_t),       # 0x10 ?
        # 0x11
    ]
    
    def struct_print(self, padding):
        p = padder(padding)
        
        print(p + 'Size    :', '0x%X' % self.Size)
        print(p + 'Checksum:', '0x%0.4X' % self.Checksum)
        print(p + 'Tag     :', self.Tag.decode('utf-8'))
        print(p + 'Flags   :', '0x%0.2X' % self.Flags)

class IntelBiosGuardHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('BGVerMajor',      uint16_t),      # 0x00
        ('BGVerMinor',      uint16_t),      # 0x02
        ('PlatformID',      uint8_t*16),    # 0x04
        ('Attributes',      uint32_t),      # 0x14
        ('ScriptVerMajor',  uint16_t),      # 0x16
        ('ScriptVerMinor',  uint16_t),      # 0x18
        ('ScriptSize',      uint32_t),      # 0x1C
        ('DataSize',        uint32_t),      # 0x20
        ('BIOSSVN',         uint32_t),      # 0x24
        ('ECSVN',           uint32_t),      # 0x28
        ('VendorInfo',      uint32_t),      # 0x2C
        # 0x30
    ]
    
    def get_platform_id(self):
        id_byte = bytes(self.PlatformID)
        
        id_text = re.sub(r'[\n\t\r\x00 ]', '', id_byte.decode('utf-8','ignore'))
        
        id_hexs = '%0.*X' % (0x10 * 2, int.from_bytes(id_byte, 'big'))
        id_guid = '{%s-%s-%s-%s-%s}' % (id_hexs[:8], id_hexs[8:12], id_hexs[12:16], id_hexs[16:20], id_hexs[20:])
        
        return '%s %s' % (id_text, id_guid)
    
    def get_flags(self):
        attr = IntelBiosGuardHeaderGetAttributes()
        attr.asbytes = self.Attributes
        
        return attr.b.SFAM, attr.b.ProtectEC, attr.b.GFXMitDis, attr.b.FTU, attr.b.Reserved
    
    def struct_print(self, padding):
        p = padder(padding)
        
        no_yes = ['No','Yes']
        f1,f2,f3,f4,f5 = self.get_flags()
        
        print(p + 'BIOS Guard Version          :', '%d.%d' % (self.BGVerMajor, self.BGVerMinor))
        print(p + 'Platform Identity           :', self.get_platform_id())
        print(p + 'Signed Flash Address Map    :', no_yes[f1])
        print(p + 'Protected EC OpCodes        :', no_yes[f2])
        print(p + 'Graphics Security Disable   :', no_yes[f3])
        print(p + 'Fault Tolerant Update       :', no_yes[f4])
        print(p + 'Attributes Reserved         :', '0x%X' % f5)
        print(p + 'Script Version              :', '%d.%d' % (self.ScriptVerMajor, self.ScriptVerMinor))
        print(p + 'Script Size                 :', '0x%X' % self.ScriptSize)
        print(p + 'Data Size                   :', '0x%X' % self.DataSize)
        print(p + 'BIOS Security Version Number:', '0x%X' % self.BIOSSVN)
        print(p + 'EC Security Version Number  :', '0x%X' % self.ECSVN)
        print(p + 'Vendor Information          :', '0x%X' % self.VendorInfo)
        
class IntelBiosGuardHeaderAttributes(ctypes.LittleEndianStructure):
    _fields_ = [
        ('SFAM',            uint32_t,       1),     # Signed Flash Address Map
        ('ProtectEC',       uint32_t,       1),     # Protected EC OpCodes
        ('GFXMitDis',       uint32_t,       1),     # GFX Security Disable
        ('FTU',             uint32_t,       1),     # Fault Tolerant Update
        ('Reserved',        uint32_t,       28)     # Reserved/Unknown
    ]

class IntelBiosGuardHeaderGetAttributes(ctypes.Union):
    _fields_ = [
        ('b',               IntelBiosGuardHeaderAttributes),
        ('asbytes',         uint32_t)
    ]

class IntelBiosGuardSignature2k(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('Unknown0',        uint32_t),      # 0x000
        ('Unknown1',        uint32_t),      # 0x004
        ('Modulus',         uint32_t*64),   # 0x008
        ('Exponent',        uint32_t),      # 0x108
        ('Signature',       uint32_t*64),   # 0x10C
        # 0x20C
    ]
    
    def struct_print(self, padding):
        p = padder(padding)
        
        Modulus = '%0.*X' % (0x100 * 2, int.from_bytes(self.Modulus, 'little'))
        Signature = '%0.*X' % (0x100 * 2, int.from_bytes(self.Signature, 'little'))
        
        print(p + 'Unknown 0:', '0x%X' % self.Unknown0)
        print(p + 'Unknown 1:', '0x%X' % self.Unknown1)
        print(p + 'Modulus  :', '%s [...]' % Modulus[:32])
        print(p + 'Exponent :', '0x%X' % self.Exponent)
        print(p + 'Signature:', '%s [...]' % Signature[:32])

def get_ami_pfat(input_buffer):
    match = PAT_AMI_PFAT.search(input_buffer)
    
    buffer = input_buffer[match.start() - 0x8:] if match else b''
    
    return match, buffer

def get_file_name(index, title):
    return safe_name('%0.2d -- %s' % (index, title))

def parse_bg_script(script_data, padding):
    is_opcode_div = len(script_data) % 8 == 0
    
    if not is_opcode_div:
        print('%sError: Script not divisible by OpCode length!' % padder(padding))
        
        return 1
    
    is_begin_end = script_data[:8] + script_data[-8:] == b'\x01' + b'\x00' * 7 + b'\xFF' + b'\x00' * 7
    
    if not is_begin_end:
        print('%sError: Script lacks Begin and/or End OpCodes!' % padder(padding))
        
        return 2
    
    BigScript = get_bgs_tool()
    
    if not BigScript:
        print('%sError: BIOS Guard Script Tool dependency missing!' % padder(padding))
        
        return 3
    
    script = BigScript(code_bytes=script_data).to_string().replace('\t','    ').split('\n')
    
    for opcode in script:
        if opcode.endswith(('begin','end')): spacing = padder(padding)
        elif opcode.endswith(':'): spacing = padder(padding + 4)
        else: spacing = padder(padding + 12)
        
        operands = [operand for operand in opcode.split(' ') if operand]
        print(spacing + ('{:<12s}' + '{:<11s}' * (len(operands) - 1)).format(*operands))
    
    return 0

def parse_pfat_hdr(buffer, padding):
    block_all = []
    
    pfat_hdr = get_struct(buffer, 0x0, AmiBiosGuardHeader)
    
    hdr_size = pfat_hdr.Size
    hdr_data = buffer[PFAT_AMI_HDR_LEN:hdr_size]
    hdr_text = hdr_data.decode('utf-8').splitlines()
    
    print('\n%sAMI BIOS Guard Header:\n' % padder(padding))
    
    pfat_hdr.struct_print(padding + 4)
    
    hdr_title,*hdr_files = hdr_text
    
    files_count = len(hdr_files)
    
    hdr_tag,*hdr_indexes = hdr_title.split('II')
    
    print('\n%s%s\n' % (padder(padding + 4), hdr_tag))
    
    bgt_indexes = [int(h, 16) for h in re.findall(r'.{1,4}', hdr_indexes[0])] if hdr_indexes else []
    
    for index,entry in enumerate(hdr_files):
        entry_parts = entry.split(';')
        
        info = entry_parts[0].split()
        name = entry_parts[1]
        
        flags = int(info[0])
        param = info[1]
        count = int(info[2])
        
        order = get_ordinal((bgt_indexes[index] if bgt_indexes else index) + 1)
        
        desc = '%s (Index: %0.2d, Flash: %s, Parameter: %s, Flags: 0x%X, Blocks: %d)' % (name, index + 1, order, param, flags, count)
        
        block_all += [(desc, name, order, param, flags, index, i, count) for i in range(count)]
    
    _ = [print(padder(padding + 8) + block[0]) for block in block_all if block[6] == 0]
    
    return block_all, hdr_size, files_count

def parse_pfat_file(buffer, output_path, padding):
    file_path = ''
    all_blocks_dict = {}
    
    extract_name = os.path.basename(output_path)
    
    extract_path = os.path.join(output_path + '_extracted', '')
    
    if os.path.isdir(extract_path): shutil.rmtree(extract_path)
    
    os.mkdir(extract_path)
    
    block_all,block_off,file_count = parse_pfat_hdr(buffer, padding)

    for block in block_all:
        file_desc,file_name,_,_,_,file_index,block_index,block_count = block
        
        if block_index == 0:
            print('\n%s%s' % (padder(padding + 4), file_desc))
            
            file_path = os.path.join(extract_path, get_file_name(file_index + 1, file_name))
            
            all_blocks_dict[file_index] = b''
        
        block_status = '%d/%d' % (block_index + 1, block_count)
        
        bg_hdr = get_struct(buffer, block_off, IntelBiosGuardHeader)
        
        print('\n%sIntel BIOS Guard %s Header:\n' % (padder(padding + 8), block_status))
        
        bg_hdr.struct_print(padding + 12)
        
        bg_script_bgn = block_off + PFAT_BLK_HDR_LEN
        bg_script_end = bg_script_bgn + bg_hdr.ScriptSize
        bg_script_bin = buffer[bg_script_bgn:bg_script_end]
        
        bg_data_bgn = bg_script_end
        bg_data_end = bg_data_bgn + bg_hdr.DataSize
        bg_data_bin = buffer[bg_data_bgn:bg_data_end]

        block_off = bg_data_end # Assume next block starts at data end

        is_sfam,_,_,_,_ = bg_hdr.get_flags() # SFAM, ProtectEC, GFXMitDis, FTU, Reserved
        
        if is_sfam:
            bg_sig_bgn = bg_data_end
            bg_sig_end = bg_sig_bgn + PFAT_BLK_S2K_LEN
            bg_sig_bin = buffer[bg_sig_bgn:bg_sig_end]
            
            if len(bg_sig_bin) == PFAT_BLK_S2K_LEN:
                bg_sig = get_struct(bg_sig_bin, 0x0, IntelBiosGuardSignature2k)
                
                print('\n%sIntel BIOS Guard %s Signature:\n' % (padder(padding + 8), block_status))
                
                bg_sig.struct_print(padding + 12)

            block_off = bg_sig_end # Adjust next block to start at data + signature end
        
        print('\n%sIntel BIOS Guard %s Script:\n' % (padder(padding + 8), block_status))
        
        _ = parse_bg_script(bg_script_bin, padding + 12)
        
        with open(file_path, 'ab') as out_dat: out_dat.write(bg_data_bin)
        
        all_blocks_dict[file_index] += bg_data_bin
    
    pfat_oob_data = buffer[block_off:] # Store out-of-bounds data after the end of PFAT files
    
    pfat_oob_path = os.path.join(extract_path, get_file_name(file_count + 1, extract_name + '_OOB.bin'))
    
    with open(pfat_oob_path, 'wb') as out_oob: out_oob.write(pfat_oob_data)
    
    oob_pfat_match,pfat_oob_buffer = get_ami_pfat(pfat_oob_data)
    
    if oob_pfat_match: parse_pfat_file(pfat_oob_buffer, pfat_oob_path, padding)
    
    in_all_data = b''.join([block[1] for block in sorted(all_blocks_dict.items())])
    
    in_all_path = os.path.join(extract_path, get_file_name(0, extract_name + '_ALL.bin'))
    
    with open(in_all_path, 'wb') as out_all: out_all.write(in_all_data + pfat_oob_data)

PFAT_AMI_HDR_LEN = ctypes.sizeof(AmiBiosGuardHeader)
PFAT_BLK_HDR_LEN = ctypes.sizeof(IntelBiosGuardHeader)
PFAT_BLK_S2K_LEN = ctypes.sizeof(IntelBiosGuardSignature2k)

if __name__ == '__main__':
    # Show script title
    show_title(title)
    
    # Set argparse Arguments    
    argparser = argparse_init()
    arguments = argparser.parse_args()
    
    # Pretty Python exception handler (must be after argparse)
    sys.excepthook = nice_exc_handler
    
    # Check Python Version (must be after argparse)
    check_sys_py()
    
    # Check OS Platform (must be after argparse)
    check_sys_os()
    
    # Process input files and generate output path
    input_files,output_path = process_input_files(arguments, sys.argv)
    
    # Initial output padding count
    padding = 4
    
    for input_file in input_files:
        input_name = os.path.basename(input_file)
        
        print('\n*** %s' % input_name)
        
        with open(input_file, 'rb') as in_file: input_buffer = in_file.read()
        
        pfat_match,pfat_buffer = get_ami_pfat(input_buffer)
        
        if not pfat_match:
            print('\n%sError: This is not an AMI BIOS Guard (PFAT) image!' % padder(padding))
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        parse_pfat_file(pfat_buffer, extract_path, padding)
    
    print_input('\nDone!')
