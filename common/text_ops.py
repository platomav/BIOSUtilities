#!/usr/bin/env python3
#coding=utf-8

# Generate padding (spaces or tabs)
def padder(count, tab=False):
    return ('\t' if tab else ' ') * count