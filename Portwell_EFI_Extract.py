#!/usr/bin/env python3
#coding=utf-8

"""
Portwell EFI Extract
Portwell EFI Update Extractor
Copyright (C) 2021-2022 Plato Mavropoulos
"""

TITLE = 'Portwell EFI Update Extractor v2.0_a6'

import os
import sys
import pefile

# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.efi_comp import efi_decompress, is_efi_compressed
from common.path_ops import safe_name, make_dirs
from common.patterns import PAT_PORTWELL_EFI, PAT_MICROSOFT_MZ
from common.system import script_init, argparse_init, printer
from common.text_ops import file_to_bytes

FILE_NAMES = {
    0 : 'Flash.efi',
    1 : 'Fparts.txt',
    2 : 'Update.nsh',
    3 : 'Temp.bin',
    4 : 'SaveDmiData.efi'
    }

# Check if input is Portwell EFI executable
def is_portwell_efi(in_file):
    in_buffer = file_to_bytes(in_file)
    
    try: pe_buffer = get_portwell_pe(in_buffer)[1]
    except: pe_buffer = b''
    
    is_mz = in_buffer.startswith(PAT_MICROSOFT_MZ.pattern) # EFI images start with PE Header MZ
    is_uu = pe_buffer.startswith(PAT_PORTWELL_EFI.pattern) # Portwell EFI files start with <UU>
    
    return is_mz and is_uu

# Get PE of Portwell EFI executable
def get_portwell_pe(in_buffer):
    pe_file = pefile.PE(data=in_buffer, fast_load=True) # Analyze EFI Portable Executable (PE)
    
    pe_data = in_buffer[pe_file.OPTIONAL_HEADER.SizeOfImage:] # Skip EFI executable (pylint: disable=E1101)
    
    return pe_file, pe_data

# Parse & Extract Portwell UEFI Unpacker
def portwell_efi_extract(input_buffer, output_path, padding=0):
    extract_path = os.path.join(f'{output_path}_extracted')
    
    make_dirs(extract_path, delete=True)
    
    pe_file,pe_data = get_portwell_pe(input_buffer)
    
    efi_title = get_unpacker_tag(input_buffer, pe_file)
    
    printer(efi_title, padding)
    
    efi_files = pe_data.split(PAT_PORTWELL_EFI.pattern) # Split EFI Payload into <UU> file chunks
    
    parse_efi_files(extract_path, efi_files[1:], padding)
    
# Get Portwell UEFI Unpacker tag
def get_unpacker_tag(input_buffer, pe_file):
    unpacker_tag_txt = 'UEFI Unpacker'
    
    for pe_section in pe_file.sections:
        # Unpacker Tag, Version, Strings etc are found in .data PE section
        if pe_section.Name.startswith(b'.data'):
            pe_data_bgn = pe_section.PointerToRawData
            pe_data_end = pe_data_bgn + pe_section.SizeOfRawData
            
            # Decode any valid UTF-16 .data PE section info to a parsable text buffer
            pe_data_txt = input_buffer[pe_data_bgn:pe_data_end].decode('utf-16','ignore')
            
            # Search .data for UEFI Unpacker tag
            unpacker_tag_bgn = pe_data_txt.find(unpacker_tag_txt)
            if unpacker_tag_bgn != -1:
                unpacker_tag_len = pe_data_txt[unpacker_tag_bgn:].find('=')
                if unpacker_tag_len != -1:
                    unpacker_tag_end = unpacker_tag_bgn + unpacker_tag_len
                    unpacker_tag_raw = pe_data_txt[unpacker_tag_bgn:unpacker_tag_end]
                    
                    # Found full UEFI Unpacker tag, store and slightly beautify the resulting text
                    unpacker_tag_txt = unpacker_tag_raw.strip().replace('   ',' ').replace('<',' <')
            
            break # Found PE .data section, skip the rest
    
    return unpacker_tag_txt

# Process Portwell UEFI Unpacker payload files
def parse_efi_files(extract_path, efi_files, padding):
    for file_index,file_data in enumerate(efi_files):
        if file_data in (b'', b'NULL'): continue # Skip empty/unused files
        
        file_name = FILE_NAMES.get(file_index, f'Unknown_{file_index}.bin') # Assign Name to EFI file  
        
        printer(file_name, padding + 4) # Print EFI file name, indicate progress
        
        if file_name.startswith('Unknown_'):
            printer(f'Note: Detected new Portwell EFI file ID {file_index}!', padding + 8, pause=True) # Report new EFI files
        
        file_path = os.path.join(extract_path, safe_name(file_name)) # Store EFI file output path
        
        with open(file_path, 'wb') as out_file: out_file.write(file_data) # Store EFI file data to drive
        
        # Attempt to detect EFI compression & decompress when applicable
        if is_efi_compressed(file_data):
            comp_fname = file_path + '.temp' # Store temporary compressed file name
            
            os.replace(file_path, comp_fname) # Rename initial/compressed file
            
            if efi_decompress(comp_fname, file_path, padding + 8) == 0:
                os.remove(comp_fname) # Successful decompression, delete compressed file

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
        
        if not is_portwell_efi(input_buffer):
            printer('Error: This is not a Portwell EFI Update Package!', padding)
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        portwell_efi_extract(input_buffer, extract_path, padding)
        
        exit_code -= 1
    
    printer('Done!', pause=True)
    
    sys.exit(exit_code)
