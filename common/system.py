#!/usr/bin/env python3
#coding=utf-8

import sys
import ctypes
import traceback

from common.text_ops import padder
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
    
    if sys_py < (3,7):
        sys.stdout.write('\nError: Python >= 3.7 required, not %d.%d!' % (sys_py[0], sys_py[1]))
        
        if not is_auto_exit():
            # noinspection PyUnresolvedReferences
            (raw_input if sys_py[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
        
        sys.exit(1)

# Check OS Platform
def check_sys_os():
    os_tag,os_win,os_sup = get_os_ver()
    
    if not os_sup:
        printer('Error: Unsupported platform "%s"!' % os_tag)
        
        if not is_auto_exit():
            input('\nPress enter to exit')
        
        sys.exit(2) 
    
    # Fix Windows Unicode console redirection
    if os_win: sys.stdout.reconfigure(encoding='utf-8')

# Show Script Title
def script_title(title):
    printer(title)
    
    _,os_win,_ = get_os_ver()
    
    # Set console/shell window title
    if os_win: ctypes.windll.kernel32.SetConsoleTitleW(title)
    else: sys.stdout.write('\x1b]2;' + title + '\x07')

# Initialize Script
def script_init(arguments, padding=0):
    # Pretty Python exception handler (must be after argparse)
    sys.excepthook = nice_exc_handler
    
    # Check Python Version (must be after argparse)
    check_sys_py()
    
    # Check OS Platform (must be after argparse)
    check_sys_os()
    
    # Process input files and generate output path
    input_files,output_path = process_input_files(arguments, sys.argv)
    
    return input_files, output_path, padding

# https://stackoverflow.com/a/781074 by Torsten Marek
def nice_exc_handler(exc_type, exc_value, tb):
    if exc_type is KeyboardInterrupt:
        printer('')
    else:
        printer('Error: Script crashed, please report the following:\n')
        
        traceback.print_exception(exc_type, exc_value, tb)

    if not is_auto_exit():
        input('\nPress enter to exit')

    sys.exit(3)

# Show message(s) while controlling padding, newline, pausing & separator
def printer(in_message='', padd_count=0, new_line=True, pause=False, sep_char=' '):    
    if type(in_message).__name__ in ('list','tuple'):
        message = sep_char.join(map(str, in_message))
    else:
        message = str(in_message)
    
    padding = padder(padd_count)
    
    newline = '\n' if new_line else ''
    
    output = newline + padding + message
    
    (input if pause and not is_auto_exit() else print)(output)