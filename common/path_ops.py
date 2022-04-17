#!/usr/bin/env python3
#coding=utf-8

"""
Copyright (C) 2022 Plato Mavropoulos
"""

import os
import re
import sys
import shutil
from pathlib import Path, PurePath

from common.text_ops import to_string

# Fix illegal/reserved Windows characters
def safe_name(in_name):
    name_repr = repr(in_name).strip("'")

    return re.sub(r'[\\/:"*?<>|]+', '_', name_repr)

# Check and attempt to fix illegal/unsafe OS path traversals
def safe_path(base_path, user_paths):
    # Convert base path to absolute path
    base_path = real_path(base_path)
    
    # Merge user path(s) to string with OS separators
    user_path = to_string(user_paths, os.sep)
    
    # Create target path from base + requested user path
    target_path = norm_path(base_path, user_path)
    
    # Check if target path is OS illegal/unsafe
    if is_safe_path(base_path, target_path):
        return target_path
    
    # Re-create target path from base + leveled/safe illegal "path" (now file)
    nuked_path = norm_path(base_path, safe_name(user_path))
    
    # Check if illegal path leveling worked
    if is_safe_path(base_path, nuked_path):
        return nuked_path
    
    # Still illegal, raise exception to halt execution
    raise Exception(f'ILLEGAL_PATH_TRAVERSAL: {user_path}')

# Check for illegal/unsafe OS path traversal
def is_safe_path(base_path, target_path):
    base_path = real_path(base_path)
    
    target_path = real_path(target_path)
    
    common_path = os.path.commonpath((base_path, target_path))
    
    return base_path == common_path

# Create normalized base path + OS separator + user path
def norm_path(base_path, user_path):
    return os.path.normpath(base_path + os.sep + user_path)

# Get absolute path, resolving any symlinks
def real_path(in_path):
    return os.path.realpath(in_path)

# Get Windows/Posix OS agnostic path
def agnostic_path(in_path):
    return PurePath(in_path.replace('\\', os.sep))

# Get absolute parent of path
def path_parent(in_path):
    return Path(in_path).parent.absolute()

# Check if path is absolute
def is_path_absolute(in_path):
    return Path(in_path).is_absolute()

# Create folder(s), controlling parents, existence and prior deletion
def make_dirs(in_path, parents=True, exist_ok=False, delete=False):
    if delete: del_dirs(in_path)
    
    Path.mkdir(Path(in_path), parents=parents, exist_ok=exist_ok)

# Delete folder(s), if present
def del_dirs(in_path):
    if Path(in_path).is_dir():
        shutil.rmtree(in_path)

# Walk path to get all files
def get_path_files(in_path):
    path_files = []
    
    for root, _, files in os.walk(in_path):
        for name in files:
            path_files.append(os.path.join(root, name))
    
    return path_files

# Get absolute file path of argparse object
def get_argparse_path(argparse_path):
    if not argparse_path:
        # Use runtime directory if no user path is specified
        absolute_path = runtime_root()
    else:
        # Check if user specified path is absolute
        if is_path_absolute(argparse_path):
            absolute_path = argparse_path
        # Otherwise, make it runtime directory relative
        else:
            absolute_path = safe_path(runtime_root(), argparse_path)
    
    return absolute_path

# Process input files (argparse object)
def process_input_files(argparse_args, sys_argv=None):
    if sys_argv is None: sys_argv = []
    
    if len(sys_argv) >= 2:
        # Drag & Drop or CLI
        if argparse_args.input_dir:
            input_path_user = argparse_args.input_dir
            input_path_full = get_argparse_path(input_path_user) if input_path_user else ''
            input_files = get_path_files(input_path_full)
        else:
            input_files = [file.name for file in argparse_args.files]
        
        # Set output path via argparse Output Path or argparse Input Path or first input file Path
        output_path = argparse_args.output_dir or argparse_args.input_dir or path_parent(input_files[0])
    else:
        # Script w/o parameters
        input_path_user = input('\nEnter input directory path: ')
        input_path_full = get_argparse_path(input_path_user) if input_path_user else ''
        input_files = get_path_files(input_path_full)
        
        output_path = input('\nEnter output directory path: ')
    
    output_path_final = get_argparse_path(output_path)
    
    return input_files, output_path_final

# Get project's root directory
def project_root():
    root = Path(__file__).parent.parent
    
    return real_path(root)

# Get runtime's root directory
def runtime_root():
    if getattr(sys, 'frozen', False):
        root = Path(sys.executable).parent
    else:
        root = project_root()
    
    return real_path(root)
