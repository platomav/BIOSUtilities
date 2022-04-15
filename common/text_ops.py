#!/usr/bin/env python3
#coding=utf-8

# Generate padding (spaces or tabs)
def padder(padd_count, tab=False):
    return ('\t' if tab else ' ') * padd_count

# Get String from given input object
def to_string(input_object, sep_char=''):
    if type(input_object).__name__ in ('list','tuple'):
        output_string = sep_char.join(map(str, input_object))
    else:
        output_string = str(input_object)
    
    return output_string
