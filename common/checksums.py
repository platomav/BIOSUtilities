#!/usr/bin/env python3
#coding=utf-8

# Get Checksum 16-bit
def checksum16(data):
    chk16 = 0
    
    for idx in range(0, len(data), 2):
        chk16 += int.from_bytes(data[idx:idx + 2], 'little')
    
    chk16 &= 0xFFFF
    
    return chk16