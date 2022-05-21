#!/usr/bin/env python3
#coding=utf-8

"""
Phoenix TDK Extract
Phoenix TDK Packer Extractor
Copyright (C) 2021-2022 Plato Mavropoulos
"""

TITLE = 'Phoenix TDK Packer Extractor v2.0_a4'

import os
import sys
import lzma
import ctypes

# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.path_ops import safe_name, make_dirs
from common.patterns import PAT_PHOENIX_TDK
from common.struct_ops import get_struct, char, uint32_t
from common.system import script_init, argparse_init, printer
from common.text_ops import file_to_bytes

class PhoenixTdkHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('Tag',             char*8),        # 0x00
        ('Size',            uint32_t),      # 0x08
        ('Count',           uint32_t),      # 0x0C
        # 0x10
    ]
    
    def _get_tag(self):
        return self.Tag.decode('utf-8','ignore').strip()
    
    def struct_print(self, p):
        printer(['Tag    :', self._get_tag()], p, False)
        printer(['Size   :', f'0x{self.Size:X}'], p, False)
        printer(['Entries:', self.Count], p, False)

class PhoenixTdkEntry(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('Name',            char*256),      # 0x000
        ('Offset',          uint32_t),      # 0x100
        ('Size',            uint32_t),      # 0x104
        ('Compressed',      uint32_t),      # 0x108
        ('Reserved',        uint32_t),      # 0x10C
        # 0x110
    ]
    
    COMP = {0: 'None', 1: 'LZMA'}
    
    def get_name(self):
        return self.Name.decode('utf-8','replace').strip()
    
    def get_compression(self):
        return self.COMP.get(self.Compressed, f'Unknown ({self.Compressed})')
    
    def struct_print(self, p):
        printer(['Name       :', self.get_name()], p, False)
        printer(['Offset     :', f'0x{self.Offset:X}'], p, False)
        printer(['Size       :', f'0x{self.Size:X}'], p, False)
        printer(['Compression:', self.get_compression()], p, False)
        printer(['Reserved   :', f'0x{self.Reserved:X}'], p, False)

# Scan input buffer for Phoenix TDK pattern
def get_phoenix_tdk(in_buffer):
    return PAT_PHOENIX_TDK.search(in_buffer)

# Check if input is Phoenix TDK image
def is_phoenix_tdk(in_file):
    buffer = file_to_bytes(in_file)
    
    return bool(get_phoenix_tdk(buffer))

# Parse & Extract Phoenix Tools Development Kit (TDK) Packer
def phoenix_tdk_extract(input_buffer, output_path, padding=0):
    exit_code = 0
    
    extract_path = os.path.join(f'{output_path}_extracted')
    
    make_dirs(extract_path, delete=True)
    
    printer('Phoenix Tools Development Kit Packer', padding)
    
    # Search for Phoenix TDK Package pattern
    tdk_match = get_phoenix_tdk(input_buffer)
    
    # Parse TDK Header structure
    tdk_hdr = get_struct(input_buffer, tdk_match.start(), PhoenixTdkHeader)
    
    # Print TDK Header structure info
    printer('Phoenix TDK Header:\n', padding + 4)
    tdk_hdr.struct_print(padding + 8)
    
    # Check if reported TDK Header Size matches manual TDK Entry Count calculation
    if tdk_hdr.Size != TDK_HDR_LEN + TDK_DUMMY_LEN + tdk_hdr.Count * TDK_MOD_LEN:
        printer('Error: Phoenix TDK Header Size & Entry Count mismatch!\n', padding + 8, pause=True)
        exit_code = 1
    
    # Store TDK Entries offset after the dummy/placeholder data
    entries_off = tdk_match.start() + TDK_HDR_LEN + TDK_DUMMY_LEN
    
    # Parse and extract each TDK Header Entry
    for entry_index in range(tdk_hdr.Count):
        # Parse TDK Entry structure
        tdk_mod = get_struct(input_buffer, entries_off + entry_index * TDK_MOD_LEN, PhoenixTdkEntry)
        
        # Print TDK Entry structure info
        printer(f'Phoenix TDK Entry ({entry_index + 1}/{tdk_hdr.Count}):\n', padding + 8)
        tdk_mod.struct_print(padding + 12)
        
        # Store TDK Entry raw data (relative to 0x0, not TDK Header)
        mod_data = input_buffer[tdk_mod.Offset:tdk_mod.Offset + tdk_mod.Size]
        
        # Check if TDK Entry raw data is complete
        if len(mod_data) != tdk_mod.Size:
            printer('Error: Phoenix TDK Entry > Data is truncated!\n', padding + 12, pause=True)
            exit_code = 2
        
        # Check if TDK Entry Reserved is present
        if tdk_mod.Reserved:
            printer('Error: Phoenix TDK Entry > Reserved is not empty!\n', padding + 12, pause=True)
            exit_code = 3            
        
        # Decompress TDK Entry raw data, when applicable (i.e. LZMA)
        if tdk_mod.get_compression() == 'LZMA':
            mod_data = lzma.LZMADecompressor().decompress(mod_data)
        
        # Generate TDK Entry file name, avoid crash if Entry data is bad
        mod_name = tdk_mod.get_name() or f'Unknown_{entry_index + 1:02d}.bin'
        
        # Generate TDK Entry file data output path
        mod_file = os.path.join(extract_path, safe_name(mod_name))
        
        # Account for potential duplicate file names
        if os.path.isfile(mod_file): mod_file += f'_{entry_index + 1:02d}'
        
        # Save TDK Entry data to output file
        with open(mod_file, 'wb') as out_file: out_file.write(mod_data)
    
    return exit_code

# Get ctypes Structure Sizes
TDK_HDR_LEN = ctypes.sizeof(PhoenixTdkHeader)
TDK_MOD_LEN = ctypes.sizeof(PhoenixTdkEntry)

# Set dummy/placeholder TDK Entries Size
TDK_DUMMY_LEN = 0x200 # Top 2, Names only

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
        
        # Check if Phoenix TDK Packer pattern was found on executable
        if not is_phoenix_tdk(input_buffer):
            printer('Error: This is not a Phoenix TDK Packer executable!', padding)
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        if phoenix_tdk_extract(input_buffer, extract_path, padding) == 0:
            exit_code -= 1
    
    printer('Done!', pause=True)
    
    sys.exit(exit_code)
