#!/usr/bin/env python3
#coding=utf-8

# https://github.com/allowitsme/big-tool by Dmitry Frolov
def get_bgs_tool():
    try:
        from external.big_script_tool import BigScript
    except:
        BigScript = None
    
    return BigScript