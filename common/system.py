#!/usr/bin/env python3
#coding=utf-8

import sys
import ctypes
import traceback

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
    return '--auto-exit' in sys.argv or '-e' in sys.argv

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
        print('\nError: Unsupported platform "%s"!' % os_tag)
        
        if not is_auto_exit():
            input('\nPress enter to exit')
        
        sys.exit(2) 
    
    # Fix Windows Unicode console redirection
    if os_win: sys.stdout.reconfigure(encoding='utf-8')

# Show Script Title
def show_title(title):
    print('\n' + title)
    
    _,os_win,_ = get_os_ver()
    
    # Set console/shell window title
    if os_win: ctypes.windll.kernel32.SetConsoleTitleW(title)
    else: sys.stdout.write('\x1b]2;' + title + '\x07')

# https://stackoverflow.com/a/781074 by Torsten Marek
def nice_exc_handler(exc_type, exc_value, tb):
    if exc_type is KeyboardInterrupt:
        print('\n')
    else:
        print('\nError: Script crashed, please report the following:\n')
        
        traceback.print_exception(exc_type, exc_value, tb)

    if not is_auto_exit():
        input('\nPress enter to exit')

    sys.exit(3)

# Print or Input Message based on --auto-exit|-e
def print_input(msg):
    (print if is_auto_exit() else input)(msg)