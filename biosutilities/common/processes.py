#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2026 Plato Mavropoulos
"""

import os
import subprocess


def popen_window_hide() -> dict:
    """ Hide external helper windows on Windows. """

    if os.name != 'nt':
        return {}

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    return {
        'creationflags': subprocess.CREATE_NO_WINDOW,
        'startupinfo': startupinfo,
    }
