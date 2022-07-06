#!/usr/bin/env python3
#coding=utf-8

"""
Toshiba COM Extract
Toshiba BIOS COM Extractor
Copyright (C) 2018-2022 Plato Mavropoulos
"""

TITLE = 'Toshiba BIOS COM Extractor v2.0_a3'

import os
import sys
import subprocess
    
# Stop __pycache__ generation
sys.dont_write_bytecode = True

from common.path_ops import make_dirs, path_stem, path_suffixes, project_root, safe_path
from common.patterns import PAT_TOSHIBA_COM
from common.system import argparse_init, get_os_ver, printer, script_init
from common.text_ops import file_to_bytes

# Check if input is Toshiba BIOS COM image
def is_toshiba_com(in_file):
    buffer = file_to_bytes(in_file)
    
    is_ext = path_suffixes(in_file)[-1].upper() == '.COM' if os.path.isfile(in_file) else True
    
    is_com = PAT_TOSHIBA_COM.search(buffer)
    
    return is_ext and is_com

# Get ToshibaComExtractor path
def get_comextract_path():
    exec_name = 'comextract.exe' if get_os_ver()[1] else 'comextract'
    
    return safe_path(project_root(), ['external',exec_name])

# Parse & Extract Toshiba BIOS COM image
def toshiba_com_extract(input_file, output_path, padding=0):
    extract_path = os.path.join(f'{output_path}_extracted')
    
    make_dirs(extract_path, delete=True)
    
    output_name = path_stem(input_file)
    output_file = os.path.join(extract_path, f'{output_name}.bin')
    
    try:
        subprocess.run([get_comextract_path(), input_file, output_file], check=True, stdout=subprocess.DEVNULL)
        
        if not os.path.isfile(output_file):
            raise Exception('EXTRACT_FILE_MISSING')
    except:
        printer(f'Error: ToshibaComExtractor could not extract file {input_file}!', padding)
        
        return 1
    
    printer(f'Succesfull {output_name} extraction via ToshibaComExtractor!', padding)
    
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
        
        if not is_toshiba_com(input_file):
            printer('Error: This is not a Toshiba BIOS COM image!', padding)
            
            continue # Next input file
        
        extract_path = os.path.join(output_path, input_name)
        
        if toshiba_com_extract(input_file, extract_path, padding) == 0:
            exit_code -= 1
    
    printer('Done!', pause=True)
    
    sys.exit(exit_code)
