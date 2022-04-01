#!/usr/bin/env python3
#coding=utf-8

import os
import subprocess

from common.script_get import get_script_dir
from common.system import get_os_ver
from common.text_ops import padder

def get_compress_sizes(data):    
    size_compress = int.from_bytes(data[0x0:0x4], 'little')
    size_original = int.from_bytes(data[0x4:0x8], 'little')
    
    return size_compress, size_original

def is_efi_compressed(data, strict=True):
    size_comp,size_orig = get_compress_sizes(data)
    
    check_diff = size_comp < size_orig
    
    if strict: check_size = size_comp + 0x8 == len(data)
    else: check_size = size_comp + 0x8 <= len(data)
    
    return check_diff and check_size

# Get TianoCompress path
def tianocompress_path():
    exec_name = 'TianoCompress' + ('.exe' if get_os_ver()[1] else '')
    
    exec_path = os.path.join(get_script_dir(), '..', 'external', exec_name)
    
    return exec_path

# EFI/Tiano Decompression via TianoCompress
def efi_decompress(in_path, out_path, padding, comp_type='--uefi'):
    try:
        subprocess.run([tianocompress_path(), '-d', in_path, '-o', out_path, '-q', comp_type], check=True, stdout=subprocess.DEVNULL)
        
        with open(in_path, 'rb') as file: _,size_orig = get_compress_sizes(file.read())
        
        if os.path.getsize(out_path) != size_orig: raise Exception('EFI_DECOMPRESS_ERROR')
        
    except:
        print('\n%sError: TianoCompress could not extract file %s!' % (padder(padding), in_path))
        
        return 1
    
    print('\n%sSuccesfull EFI/Tiano decompression via TianoCompress!' % padder(padding))
    
    return 0