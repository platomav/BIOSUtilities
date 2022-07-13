#!/usr/bin/env python3
#coding=utf-8

"""
Fujitsu SFX Extractor
Fujitsu SFX BIOS Extractor
Copyright (C) 2019-2022 Plato Mavropoulos
"""

TITLE = 'Fujitsu SFX BIOS Extractor v3.0_a2'

import os
import sys

# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.comp_szip import is_szip_supported, szip_decompress
from common.path_ops import make_dirs
from common.patterns import PAT_FUJITSU_SFX
from common.system import argparse_init, printer, script_init
from common.text_ops import file_to_bytes

# Check if input is Fujitsu SFX image
def is_fujitsu_sfx(in_file):
    buffer = file_to_bytes(in_file)
    
    return bool(PAT_FUJITSU_SFX.search(buffer))

# Extract Fujitsu SFX image
def fujitsu_cabinet(in_file, extract_path, padding=0):
    buffer = file_to_bytes(in_file)
    
    match_cab = PAT_FUJITSU_SFX.search(buffer) # Microsoft CAB Header XOR 0xFF
    
    if not match_cab:
        return 1
    
    printer('Detected obfuscated CAB archive!', padding)
    
    # Microsoft CAB Header XOR 0xFF starts after "FjSfxBinay" signature
    cab_start = match_cab.start() + 0xA
    
    # Determine the Microsoft CAB image size
    cab_size = int.from_bytes(buffer[cab_start + 0x8:cab_start + 0xC], 'little') # Get LE XOR-ed CAB size
    xor_size = int.from_bytes(b'\xFF' * 0x4, 'little') # Create CAB size XOR value
    cab_size ^= xor_size # Perform XOR 0xFF and get actual CAB size

    printer('Removing obfuscation...', padding + 4)
    
    # Determine the Microsoft CAB image Data
    cab_data = int.from_bytes(buffer[cab_start:cab_start + cab_size], 'big') # Get BE XOR-ed CAB data
    xor_data = int.from_bytes(b'\xFF' * cab_size, 'big') # Create CAB data XOR value
    cab_data = (cab_data ^ xor_data).to_bytes(cab_size, 'big') # Perform XOR 0xFF and get actual CAB data
    
    printer('Extracting archive...', padding + 4)
    
    cab_path = os.path.join(extract_path, 'FjSfxBinay.cab')
    
    with open(cab_path, 'wb') as cab_file:
        cab_file.write(cab_data) # Create temporary CAB archive
    
    if is_szip_supported(cab_path, padding + 8, check=True):
        if szip_decompress(cab_path, extract_path, 'CAB', padding + 8, check=True) == 0:
            os.remove(cab_path) # Successful extraction, delete temporary CAB archive
        else:
            return 3
    else:
        return 2
    
    return 0

# Parse & Extract Fujitsu SFX image
def fujitsu_sfx_extract(in_file, output_path, padding=0):
    buffer = file_to_bytes(in_file)
    
    extract_path = os.path.join(f'{output_path}_extracted')
    
    make_dirs(extract_path, delete=True)
    
    if fujitsu_cabinet(buffer, extract_path, padding) == 0:
        printer('Successfully Extracted!', padding)
    else:
        printer('Error: Failed to Extract image!', padding)
        return 1
    
    return 0

if __name__ == '__main__':
    # Set argparse Arguments    
    argparser = argparse_init()
    arguments = argparser.parse_args()
    
    # Initialize script (must be after argparse)
    exit_code,input_files,output_path,padding = script_init(TITLE, arguments, 4)
    
    for input_file in input_files:
        input_name = os.path.basename(input_file)
        
        printer(['***', input_name], padding - 4)
        
        with open(input_file, 'rb') as in_file:
            input_buffer = in_file.read()
        
        # Check if Fujitsu SFX pattern was found on image
        if not is_fujitsu_sfx(input_buffer):
            printer('Error: This is not a Fujitsu SFX image!', padding)
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        if fujitsu_sfx_extract(input_buffer, extract_path, padding) == 0:
            exit_code -= 1
    
    printer('Done!', pause=True)
    
    sys.exit(exit_code)
