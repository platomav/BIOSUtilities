#!/usr/bin/env python3
#coding=utf-8

"""
Copyright (C) 2022 Plato Mavropoulos
"""

import sys
import ctypes
import argparse
import traceback

from common.text_ops import padder, to_string
from common.path_ops import process_input_files

# Get Python Version (tuple)
def get_py_ver():
    return sys.version_info

# Get OS Platform (string)
def get_os_ver():
    sys_os = sys.platform
    
    is_win = sys_os == 'win32'
    is_lnx = sys_os.startswith('linux') or sys_os == 'darwin' or sys_os.find('bsd') != -1
    
    return sys_os, is_win, is_win or is_lnx

# Check for --auto-exit|-e
def is_auto_exit():
    return bool('--auto-exit' in sys.argv or '-e' in sys.argv)

# Check Python Version
def check_sys_py():
    sys_py = get_py_ver()
    
    if sys_py < (3,8):
        sys.stdout.write(f'\nError: Python >= 3.8 required, not {sys_py[0]}.{sys_py[1]}!')
        
        if not is_auto_exit():
            # noinspection PyUnresolvedReferences
            (raw_input if sys_py[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
        
        sys.exit(125)

# Check OS Platform
def check_sys_os():
    os_tag,os_win,os_sup = get_os_ver()
    
    if not os_sup:
        printer(f'Error: Unsupported platform "{os_tag}"!')
        
        if not is_auto_exit():
            input('\nPress enter to exit')
        
        sys.exit(126) 
    
    # Fix Windows Unicode console redirection
    if os_win:
        sys.stdout.reconfigure(encoding='utf-8')

# Initialize common argparse arguments
def argparse_init():
    argparser = argparse.ArgumentParser()
    
    argparser.add_argument('files', type=argparse.FileType('r'), nargs='*')
    argparser.add_argument('-e', '--auto-exit', help='skip press enter to exit prompts', action='store_true')
    argparser.add_argument('-v', '--version', help='show utility name and version', action='store_true')
    argparser.add_argument('-o', '--output-dir', help='extract in given output directory')
    argparser.add_argument('-i', '--input-dir', help='extract from given input directory')
    
    return argparser

# Initialize Script (must be after argparse)
def script_init(title, arguments, padding=0):
    # Pretty Python exception handler
    sys.excepthook = nice_exc_handler
    
    # Check Python Version
    check_sys_py()
    
    # Check OS Platform
    check_sys_os()
    
    # Show Script Title
    printer(title, new_line=False)
    
    # Show Utility Version on demand
    if arguments.version:
        sys.exit(0)
    
    # Set console/terminal window title (Windows only)
    if get_os_ver()[1]:
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    
    # Process input files and generate output path
    input_files,output_path = process_input_files(arguments, sys.argv)
    
    # Count input files for exit code
    input_count = len(input_files)
    
    return input_count, input_files, output_path, padding

# https://stackoverflow.com/a/781074 by Torsten Marek
def nice_exc_handler(exc_type, exc_value, tb):
    if exc_type is KeyboardInterrupt:
        printer('')
    else:
        printer('Error: Script crashed, please report the following:\n')
        
        traceback.print_exception(exc_type, exc_value, tb)

    if not is_auto_exit():
        input('\nPress enter to exit')

    sys.exit(127)

# Show message(s) while controlling padding, newline, pausing & separator
def printer(in_message='', padd_count=0, new_line=True, pause=False, sep_char=' '):
    message = to_string(in_message, sep_char)
    
    padding = padder(padd_count)
    
    newline = '\n' if new_line else ''
    
    output = newline + padding + message
    
    (input if pause and not is_auto_exit() else print)(output)
