#!/usr/bin/env python3
#coding=utf-8

"""
Insyde iFlash Extract
Insyde iFlash Update Extractor
Copyright (C) 2022 Plato Mavropoulos
"""

TITLE = 'Insyde iFlash Update Extractor v2.0_a2'

import os
import sys
import ctypes
    
# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.path_ops import make_dirs, safe_name
from common.patterns import PAT_INSYDE_IFL
from common.struct_ops import get_struct, char, uint32_t
from common.system import script_init, argparse_init, printer
from common.text_ops import file_to_bytes

class IflashHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('Signature',       char*9),        # 0x00 $_IFLASH_
        ('ImageTag',        char*7),        # 0x08
        ('TotalSize',       uint32_t),      # 0x10 from header end
        ('ImageSize',       uint32_t),      # 0x14 from header end
        # 0x18
    ]
    
    def struct_print(self, p):
        printer(['Signature :', self.Signature.decode('utf-8','ignore')], p, False)
        printer(['Image Name:', self.ImageTag.decode('utf-8','ignore')], p, False)
        printer(['Image Size:', f'0x{self.ImageSize:X}'], p, False)
        printer(['Total Size:', f'0x{self.TotalSize:X}'], p, False)

# Parse & Extract Insyde iFlash Update image
def insyde_iflash_extract(input_buffer, ins_ifl_all, output_path, padding=0):
    extract_path = os.path.join(f'{output_path}_extracted')
    
    make_dirs(extract_path, delete=True)
    
    for ins_ifl_val in ins_ifl_all:
        ins_ifl_off,ins_ifl_hdr = ins_ifl_val
        
        mod_bgn = ins_ifl_off + IFL_HDR_LEN
        mod_end = mod_bgn + ins_ifl_hdr.ImageSize
        mod_bin = input_buffer[mod_bgn:mod_end]
        
        mod_val = [ins_ifl_hdr.ImageTag.decode('utf-8','ignore'), 'bin']
        mod_tag,mod_ext = IFL_MOD_NAMES.get(mod_val[0], mod_val)
        
        mod_name = f'{mod_tag} [0x{mod_bgn:08X}-0x{mod_end:08X}]'
        
        printer(f'{mod_name}\n', padding)
        
        ins_ifl_hdr.struct_print(padding + 4)
        
        if mod_val == [mod_tag,mod_ext]:
            printer(f'Note: Detected new Insyde iFlash image tag {mod_tag}!', padding + 8, pause=True)
        
        out_name = f'{mod_name}.{mod_ext}'
        
        out_path = os.path.join(extract_path, safe_name(out_name))
        
        with open(out_path, 'wb') as out: out.write(mod_bin)
        
        printer('Succesfull Insyde iFlash image extraction!', padding + 8)

# Get Insyde iFlash Update image matches
def get_insyde_iflash(in_file):
    ins_ifl_all = []
    ins_ifl_nan = [0x0,0xFFFFFFFF]
    
    buffer = file_to_bytes(in_file)
    
    for ins_ifl_match in PAT_INSYDE_IFL.finditer(buffer):
        ins_ifl_off = ins_ifl_match.start()

        if len(buffer[ins_ifl_off:]) <= IFL_HDR_LEN:
            continue
        
        ins_ifl_hdr = get_struct(buffer, ins_ifl_off, IflashHeader)
        
        if ins_ifl_hdr.TotalSize in ins_ifl_nan \
        or ins_ifl_hdr.ImageSize in ins_ifl_nan \
        or ins_ifl_hdr.TotalSize <= ins_ifl_hdr.ImageSize:
            continue
        
        ins_ifl_all.append([ins_ifl_off, ins_ifl_hdr])
    
    return ins_ifl_all

# Check if input is Insyde iFlash Update image
def is_insyde_iflash(in_file):
    buffer = file_to_bytes(in_file)
    
    return bool(get_insyde_iflash(buffer))

IFL_MOD_NAMES = {
    'DRV_IMG' : ['isflash', 'efi'],
    'INI_IMG' : ['platform', 'ini'],
    'BIOSIMG' : ['BIOS-UEFI', 'bin'],
    'ME_IMG_' : ['Management Engine', 'bin'],
    'EC_IMG_' : ['Embedded Controller', 'bin'],
    'OEM_ID_' : ['OEM Identifier', 'bin'],
    'BIOSCER' : ['Certificate', 'bin'],
    'BIOSCR2' : ['Certificate 2nd', 'bin'],
    }

# Get common ctypes Structure Sizes
IFL_HDR_LEN = ctypes.sizeof(IflashHeader)

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
        
        ins_ifl_all = get_insyde_iflash(input_buffer)
        
        if not ins_ifl_all:
            printer('Error: This is not an Insyde iFlash Update image!', padding)
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        insyde_iflash_extract(input_buffer, ins_ifl_all, extract_path, padding)
        
        exit_code -= 1
    
    printer('Done!', pause=True)
    
    sys.exit(exit_code)
