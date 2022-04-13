#!/usr/bin/env python3
#coding=utf-8

import os
import re
import sys
import inspect
from pathlib import Path

# Fix illegal/reserved Windows characters
def safe_name(in_name):
    raw_name = repr(in_name).strip("'")

    fix_name = re.sub(r'[\\/*?:"<>|]', '_', raw_name)

    return fix_name

# Walk path to get all files
def get_path_files(in_path):
    path_files = []
    
    for root, _, files in os.walk(in_path):
        for name in files:
            path_files.append(os.path.join(root, name))
    
    return path_files

# Get parent of path
def get_path_parent(in_path):
    return Path(in_path).parent.absolute()

# Get absolute file path (argparse object)
def get_absolute_path(argparse_path):
    script_dir = get_path_parent(get_script_dir())
    
    if not argparse_path:
        absolute_path = script_dir # Use input file directory if no user path is specified
    else:
        # Check if user specified path is absolute, otherwise convert it to input file relative
        if Path(argparse_path).is_absolute(): absolute_path = argparse_path
        else: absolute_path = os.path.join(script_dir, argparse_path)
    
    return absolute_path

# Process input files (argparse object)
def process_input_files(argparse_args, sys_argv=None):
    if sys_argv is None: sys_argv = []
    
    if len(sys_argv) >= 2:
        # Drag & Drop or CLI
        if argparse_args.input_dir:
            input_path_user = argparse_args.input_dir
            input_path_full = get_absolute_path(input_path_user) if input_path_user else ''
            input_files = get_path_files(input_path_full)
        else:
            input_files = [file.name for file in argparse_args.files]
        
        output_path = get_absolute_path(argparse_args.output_dir or argparse_args.input_dir)
    else:
        # Script w/o parameters
        input_path_user = input('\nEnter input directory path: ')
        input_path_full = get_absolute_path(input_path_user) if input_path_user else ''
        input_files = get_path_files(input_path_full)
        
        output_path = get_absolute_path(input('\nEnter output directory path: '))
    
    return input_files, output_path

# https://stackoverflow.com/a/22881871 by jfs
def get_script_dir(follow_symlinks=True):
    if getattr(sys, 'frozen', False):
        path = os.path.abspath(sys.executable)
    else:
        path = inspect.getabsfile(get_script_dir)
    
    if follow_symlinks:
        path = os.path.realpath(path)

    return os.path.dirname(path)