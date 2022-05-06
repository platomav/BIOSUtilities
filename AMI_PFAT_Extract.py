#!/usr/bin/env python3
#coding=utf-8

"""
AMI PFAT Extract
AMI BIOS Guard Extractor
Copyright (C) 2018-2022 Plato Mavropoulos
"""

TITLE = 'AMI BIOS Guard Extractor v4.0_a9'

import os
import re
import sys
import ctypes

# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.externals import get_bgs_tool
from common.num_ops import get_ordinal
from common.path_ops import safe_name, make_dirs
from common.patterns import PAT_AMI_PFAT
from common.struct_ops import get_struct, char, uint8_t, uint16_t, uint32_t
from common.system import script_init, argparse_init, printer
from common.text_ops import file_to_bytes

class AmiBiosGuardHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('Size',            uint32_t),      # 0x00 Header + Entries
        ('Checksum',        uint32_t),      # 0x04 ?
        ('Tag',             char*8),        # 0x04 _AMIPFAT
        ('Flags',           uint8_t),       # 0x10 ?
        # 0x11
    ]
    
    def struct_print(self, p):
        printer(['Size    :', '0x%X' % self.Size], p, False)
        printer(['Checksum:', '0x%0.4X' % self.Checksum], p, False)
        printer(['Tag     :', self.Tag.decode('utf-8')], p, False)
        printer(['Flags   :', '0x%0.2X' % self.Flags], p, False)

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
    
    def struct_print(self, p):
        no_yes = ['No','Yes']
        f1,f2,f3,f4,f5 = self.get_flags()
        
        printer(['BIOS Guard Version          :', '%d.%d' % (self.BGVerMajor, self.BGVerMinor)], p, False)
        printer(['Platform Identity           :', self.get_platform_id()], p, False)
        printer(['Signed Flash Address Map    :', no_yes[f1]], p, False)
        printer(['Protected EC OpCodes        :', no_yes[f2]], p, False)
        printer(['Graphics Security Disable   :', no_yes[f3]], p, False)
        printer(['Fault Tolerant Update       :', no_yes[f4]], p, False)
        printer(['Attributes Reserved         :', '0x%X' % f5], p, False)
        printer(['Script Version              :', '%d.%d' % (self.ScriptVerMajor, self.ScriptVerMinor)], p, False)
        printer(['Script Size                 :', '0x%X' % self.ScriptSize], p, False)
        printer(['Data Size                   :', '0x%X' % self.DataSize], p, False)
        printer(['BIOS Security Version Number:', '0x%X' % self.BIOSSVN], p, False)
        printer(['EC Security Version Number  :', '0x%X' % self.ECSVN], p, False)
        printer(['Vendor Information          :', '0x%X' % self.VendorInfo], p, False)
        
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
    
    def struct_print(self, p):
        Modulus = '%0.*X' % (0x100 * 2, int.from_bytes(self.Modulus, 'little'))
        Signature = '%0.*X' % (0x100 * 2, int.from_bytes(self.Signature, 'little'))
        
        printer(['Unknown 0:', '0x%X' % self.Unknown0], p, False)
        printer(['Unknown 1:', '0x%X' % self.Unknown1], p, False)
        printer(['Modulus  :', '%s [...]' % Modulus[:32]], p, False)
        printer(['Exponent :', '0x%X' % self.Exponent], p, False)
        printer(['Signature:', '%s [...]' % Signature[:32]], p, False)

def is_ami_pfat(in_file):
    input_buffer = file_to_bytes(in_file)
    
    return bool(get_ami_pfat(input_buffer)[0])

def get_ami_pfat(input_buffer):
    match = PAT_AMI_PFAT.search(input_buffer)
    
    buffer = input_buffer[match.start() - 0x8:] if match else b''
    
    return match, buffer

def get_file_name(index, name):
    return safe_name('%0.2d -- %s' % (index, name))

def parse_bg_script(script_data, padding):
    is_opcode_div = len(script_data) % 8 == 0
    
    if not is_opcode_div:
        printer('Error: Script not divisible by OpCode length!', padding, False)
        
        return 1
    
    is_begin_end = script_data[:8] + script_data[-8:] == b'\x01' + b'\x00' * 7 + b'\xFF' + b'\x00' * 7
    
    if not is_begin_end:
        printer('Error: Script lacks Begin and/or End OpCodes!', padding, False)
        
        return 2
    
    BigScript = get_bgs_tool()
    
    if not BigScript:
        printer('Error: BIOS Guard Script Tool dependency missing!', padding, False)
        
        return 3
    
    script = BigScript(code_bytes=script_data).to_string().replace('\t','    ').split('\n')
    
    for opcode in script:
        if opcode.endswith(('begin','end')): spacing = padding
        elif opcode.endswith(':'): spacing = padding + 4
        else: spacing = padding + 12
        
        operands = [operand for operand in opcode.split(' ') if operand]
        printer(('{:<12s}' + '{:<11s}' * (len(operands) - 1)).format(*operands), spacing, False)
    
    return 0

def parse_pfat_hdr(buffer, padding):
    block_all = []
    
    pfat_hdr = get_struct(buffer, 0x0, AmiBiosGuardHeader)
    
    hdr_size = pfat_hdr.Size
    hdr_data = buffer[PFAT_AMI_HDR_LEN:hdr_size]
    hdr_text = hdr_data.decode('utf-8').splitlines()
    
    printer('AMI BIOS Guard Header:\n', padding)
    
    pfat_hdr.struct_print(padding + 4)
    
    hdr_title,*hdr_files = hdr_text
    
    files_count = len(hdr_files)
    
    hdr_tag,*hdr_indexes = hdr_title.split('II')
    
    printer(hdr_tag + '\n', padding + 4)
    
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
    
    _ = [printer(block[0], padding + 8, False) for block in block_all if block[6] == 0]
    
    return block_all, hdr_size, files_count

def parse_pfat_file(buffer, output_path, padding):
    file_path = ''
    all_blocks_dict = {}
    
    extract_name = os.path.basename(output_path)
    
    extract_path = os.path.join(output_path + '_extracted')
    
    make_dirs(extract_path, delete=True)
    
    block_all,block_off,file_count = parse_pfat_hdr(buffer, padding)

    for block in block_all:
        file_desc,file_name,_,_,_,file_index,block_index,block_count = block
        
        if block_index == 0:
            printer(file_desc, padding + 4)
            
            file_path = os.path.join(extract_path, get_file_name(file_index + 1, file_name))
            
            all_blocks_dict[file_index] = b''
        
        block_status = '%d/%d' % (block_index + 1, block_count)
        
        bg_hdr = get_struct(buffer, block_off, IntelBiosGuardHeader)
        
        printer('Intel BIOS Guard %s Header:\n' % block_status, padding + 8)
        
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
                
                printer('Intel BIOS Guard %s Signature:\n' % block_status, padding + 8)
                
                bg_sig.struct_print(padding + 12)

            block_off = bg_sig_end # Adjust next block to start at data + signature end
        
        printer('Intel BIOS Guard %s Script:\n' % block_status, padding + 8)
        
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
    # Set argparse Arguments    
    argparser = argparse_init()
    arguments = argparser.parse_args()
    
    # Initialize script (must be after argparse)
    exit_code,input_files,output_path,padding = script_init(TITLE, arguments, 4)
    
    for input_file in input_files:
        input_name = os.path.basename(input_file)
        
        printer(['***', input_name], padding - 4)
        
        with open(input_file, 'rb') as in_file: input_buffer = in_file.read()
        
        pfat_match,pfat_buffer = get_ami_pfat(input_buffer)
        
        if not pfat_match:
            printer('Error: This is not an AMI BIOS Guard (PFAT) image!', padding)
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        parse_pfat_file(pfat_buffer, extract_path, padding)
        
        exit_code -= 1
    
    printer('Done!', pause=True)
    
    sys.exit(exit_code)
