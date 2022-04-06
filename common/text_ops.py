#!/usr/bin/env python3
#coding=utf-8

# Generate padding (spaces or tabs)
def padder(padd_count, tab=False):
    return ('\t' if tab else ' ') * padd_count