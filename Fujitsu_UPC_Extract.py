#!/usr/bin/env python3
#coding=utf-8

"""
Fujitsu UPC Extract
Fujitsu UPC BIOS Extractor
Copyright (C) 2021-2022 Plato Mavropoulos
"""

TITLE = 'Fujitsu UPC BIOS Extractor v2.0_a2'

import os
import sys
    
# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.comp_efi import efi_decompress, is_efi_compressed
from common.path_ops import make_dirs, path_suffixes
from common.system import script_init, argparse_init, printer
from common.text_ops import file_to_bytes

# Check if input is Fujitsu UPC image
def is_fujitsu_upc(in_file):
    in_buffer = file_to_bytes(in_file)
    
    is_upc = path_suffixes(in_file)[-1].upper() == '.UPC' if os.path.isfile(in_file) else True
    
    is_efi = is_efi_compressed(in_buffer)
    
    return is_upc and is_efi

# Parse & Extract Fujitsu UPC image
def fujitsu_upc_extract(input_file, output_path, padding=0):
    extract_path = os.path.join(f'{output_path}_extracted')
    
    make_dirs(extract_path, delete=True)
    
    image_base = os.path.basename(input_file)
    image_name = image_base[:-4] if image_base.upper().endswith('.UPC') else image_base
    image_path = os.path.join(extract_path, f'{image_name}.bin')
    
    return efi_decompress(input_file, image_path, padding)
    
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
        
        if not is_fujitsu_upc(input_buffer):
            printer('Error: This is not a Fujitsu UPC BIOS image!', padding)
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        if fujitsu_upc_extract(input_file, extract_path, padding) == 0:
            exit_code -= 1
    
    printer('Done!', pause=True)
    
    sys.exit(exit_code)
