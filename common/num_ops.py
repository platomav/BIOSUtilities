#!/usr/bin/env python3 -B
# coding=utf-8

"""
Copyright (C) 2022-2024 Plato Mavropoulos
"""


def get_ordinal(number):
    """
    Get ordinal (textual) representation of input numerical value
    https://leancrew.com/all-this/2020/06/ordinals-in-python/ by Dr. Drang
    """

    txt = ('th', 'st', 'nd', 'rd') + ('th',) * 10

    val = number % 100

    return f'{number}{txt[val % 10]}' if val > 13 else f'{number}{txt[val]}'
