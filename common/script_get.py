#!/usr/bin/env python3
#coding=utf-8

# https://stackoverflow.com/a/22881871 by jfs

import os
import sys
import inspect

def get_script_dir(follow_symlinks=True):
    if getattr(sys, 'frozen', False):
        path = os.path.abspath(sys.executable)
    else:
        path = inspect.getabsfile(get_script_dir)
    
    if follow_symlinks:
        path = os.path.realpath(path)

    return os.path.dirname(path)