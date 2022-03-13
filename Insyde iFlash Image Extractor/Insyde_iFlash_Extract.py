#!/usr/bin/env python3
#coding=utf-8

"""
Insyde iFlash Extract
Insyde iFlash Image Extractor
Copyright (C) 2022 Plato Mavropoulos
"""

title = 'Insyde iFlash Image Extractor v1.0'

import sys

# Detect Python version
sys_py = sys.version_info

# Check Python version
if sys_py < (3,7):
    sys.stdout.write('%s\n\nError: Python >= 3.7 required, not %d.%d!\n' % (title, sys_py[0], sys_py[1]))
    
    if '--auto-exit' not in sys.argv and '-e' not in sys.argv:
        (raw_input if sys_py[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
    
    sys.exit(1)

# Detect OS platform
sys_os = sys.platform

# Check OS platform
if sys_os == 'win32':
    sys.stdout.reconfigure(encoding='utf-8') # Fix Windows Unicode console redirection
elif sys_os.startswith('linux') or sys_os == 'darwin' or sys_os.find('bsd') != -1:
    pass # Supported/Tested
else:
    print('%s\n\nError: Unsupported platform "%s"!\n' % (title, sys_os))
    
    if '--auto-exit' not in sys.argv and '-e' not in sys.argv: input('Press enter to exit')
    
    sys.exit(1)

# Python imports
import os
import re
import ctypes
import inspect
import pathlib
import argparse
import traceback

# Set ctypes Structure types
char = ctypes.c_char
uint32_t = ctypes.c_uint

class IflashHeader(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('Signature',            char*9),        # 0x00 $_IFLASH_
        ('ImageTag',             char*7),        # 0x08
        ('TotalSize',            uint32_t),      # 0x10 from header end
        ('ImageSize',            uint32_t),      # 0x14 from header end
        # 0x18
    ]
    
    def ifl_print(self, padd):
        p = ' ' * (padd - 1)
        
        print(p, 'Signature : %s' % self.Signature.decode('utf-8','ignore'))
        print(p, 'Image Name: %s' % self.ImageTag.decode('utf-8','ignore'))
        print(p, 'Total Size: 0x%X' % self.TotalSize)
        print(p, 'Image Size: 0x%X' % self.ImageSize)

class InsydeIflash:
    def __init__(self, in_data, out_path, in_padd, in_verbose):
        self.fw_data = in_data
        self.ex_path = out_path
        self.padding = in_padd
        self.verbose = in_verbose
        
        self.hdr_len = ctypes.sizeof(IflashHeader)
        
        self.mod_names = {
            'DRV_IMG':['isflash','efi'],
            'INI_IMG':['platform','ini'],
            'BIOSIMG':['BIOS','bin'],
            'ME_IMG_':['ME','bin'],
            'EC_IMG_':['EC','bin'],
            'OEM_ID_':['OEM_ID','bin'],
            'BIOSCER':['Certificate','bin'],
            'BIOSCR2':['Certificate_2','bin'],
            }

    def iflash_parse(self):
        all_ins_ifl = pat_ins_ifl.finditer(self.fw_data)
        
        if not all_ins_ifl: return 1
        
        if not os.path.isdir(self.ex_path): os.mkdir(self.ex_path)
        
        for ins_ifl in all_ins_ifl:
            ifl_off = ins_ifl.start()
            
            ifl_hdr = get_struct(self.fw_data, ifl_off, IflashHeader)
            
            if self.verbose:
                print('\n%sInsyde iFlash Module @ 0x%0.8X\n' % (' ' * self.padding, ifl_off))
                
                ifl_hdr.ifl_print(self.padding + 4)
            
            mod_bgn = ifl_off + self.hdr_len
            mod_end = mod_bgn + ifl_hdr.ImageSize
            mod_bin = self.fw_data[mod_bgn:mod_end]
            
            if not mod_bin: continue # Empty/Missing Module
            
            mod_tag = ifl_hdr.ImageTag.decode('utf-8','ignore')
            out_tag = self.mod_names[mod_tag][0] if mod_tag in self.mod_names else mod_tag
            out_ext = self.mod_names[mod_tag][1] if mod_tag in self.mod_names else 'bin'
            
            out_name = get_safe_name('%s [0x%0.8X-0x%0.8X].%s' % (out_tag, mod_bgn, mod_end, out_ext))
            out_path = os.path.join(self.ex_path, out_name)

            with open(out_path, 'wb') as out: out.write(mod_bin)
            
            print('\n%sExtracted' % (' ' * (self.padding + 8 if self.verbose else self.padding)), out_name)

        return 0

# Process ctypes Structure Classes
# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
def get_struct(buffer, start_offset, class_name, param_list=None):
    if param_list is None: param_list = []

    structure = class_name(*param_list) # Unpack parameter list
    struct_len = ctypes.sizeof(structure)
    struct_data = buffer[start_offset:start_offset + struct_len]
    fit_len = min(len(struct_data), struct_len)

    ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)

    return structure

# Get absolute file path (argparse object)
def get_absolute_path(argparse_path):
    if not argparse_path:
        absolute_path = get_script_dir() # Use input file directory if no user path is specified
    else:
        # Check if user specified path is absolute, otherwise convert it to input file relative
        if pathlib.Path(argparse_path).is_absolute(): absolute_path = argparse_path
        else: absolute_path = os.path.join(get_script_dir(), argparse_path)
    
    return absolute_path

# Get list of files from absolute path
def get_path_files(abs_path):
    file_list = [] # Initialize list of files
    
    # Traverse input absolute path
    for root,_,files in os.walk(abs_path):
        file_list = [os.path.join(root, name) for name in files]
    
    return file_list

# Fix illegal/reserved Windows characters
def get_safe_name(file_name):
    raw_name = repr(file_name).strip("'")

    return re.sub(r'[\\/*?:"<>|]', '_', raw_name)

# Get python script working directory
# https://stackoverflow.com/a/22881871 by jfs
def get_script_dir(follow_symlinks=True):
    if getattr(sys, 'frozen', False):
        path = os.path.abspath(sys.executable)
    else:
        path = inspect.getabsfile(get_script_dir)
    if follow_symlinks:
        path = os.path.realpath(path)

    return os.path.dirname(path)

# Pause after any unexpected Python exception
# https://stackoverflow.com/a/781074 by Torsten Marek
def show_exception_and_exit(exc_type, exc_value, tb):
    if exc_type is KeyboardInterrupt :
        print('\n')
    else:
        print('\nError: %s crashed, please report the following:\n' % title)
        traceback.print_exception(exc_type, exc_value, tb)
        if not bool(args.auto_exit): input('\nPress enter to exit')
    
    sys.exit(1) # Crash exceptions are critical

# Insyde iFlash Section Signature
pat_ins_ifl = re.compile(br'\$_IFLASH_')

if __name__ == '__main__':
    # Show script title
    print('\n' + title)

    # Set console/shell window title
    user_os = sys.platform
    if user_os == 'win32': ctypes.windll.kernel32.SetConsoleTitleW(title)
    elif user_os.startswith('linux') or user_os == 'darwin' or user_os.find('bsd') != -1: sys.stdout.write('\x1b]2;' + title + '\x07')

    # Set argparse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('images', type=argparse.FileType('r'), nargs='*')
    parser.add_argument('-v', '--verbose', help='show iFlash structure information', action='store_true')
    parser.add_argument('-e', '--auto-exit', help='skip press enter to exit prompts', action='store_true')
    parser.add_argument('-o', '--output-dir', help='extract in given output directory')
    parser.add_argument('-i', '--input-dir', help='extract from given input directory')
    args = parser.parse_args()
    
    # Set pause-able Python exception handler (must be after args)
    sys.excepthook = show_exception_and_exit
    
    # Initialize Dell PFS input file list
    iflash_input_images = []

    # Process input files
    if len(sys.argv) >= 2:
        # Drag & Drop or CLI
        if args.input_dir:
            input_path_user = get_absolute_path(args.input_dir)
            iflash_input_images = get_path_files(input_path_user)
        else:
            iflash_input_images = [image.name for image in args.images]
        
        output_path_user = get_absolute_path(args.output_dir or args.input_dir)
    else:
        # Script w/o parameters
        input_path_user = get_absolute_path(input('\nEnter input directory path: '))
        iflash_input_images = get_path_files(input_path_user)
        
        output_path_user = get_absolute_path(input('\nEnter output directory path: '))

    # Initialize global variables
    exit_code = len(iflash_input_images) # Initialize exit code with input file count
    is_verbose = bool(args.verbose) # Set Verbose output mode optional argument
    
    for input_file in iflash_input_images:
        input_name = os.path.basename(input_file)
        input_padd = 8
        
        print('\n*** %s' % input_name)
        
        # Check if input file exists
        if not os.path.isfile(input_file):
            print('\n%sError: This input file does not exist!' % (' ' * input_padd))
            continue # Next input file
        
        with open(input_file, 'rb') as in_file: input_data = in_file.read()
        
        # Search input image for Insyde iFlash Sections
        is_ins_ifl = pat_ins_ifl.search(input_data)
        
        if not is_ins_ifl:
            print('\n%sError: This is not an Insyde iFlash image!' % (' ' * input_padd))
            continue # Next input file
        
        # Set main extraction path (optional user specified path taken into account)
        output_path = os.path.join(output_path_user, input_name + '_extracted')
        
        InsydeIflash(input_data, output_path, input_padd, is_verbose).iflash_parse()
        
        exit_code -= 1 # Adjust exit code to reflect extraction progress
    
    if not bool(args.auto_exit): input('\nDone!')
    
    sys.exit(exit_code)
