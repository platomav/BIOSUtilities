#!/usr/bin/env python3

"""
Award BIOS Extract
Award BIOS Module Extractor
Copyright (C) 2018 Plato Mavropoulos
http://www.onicos.com/staff/iz/formats/lzh.html
https://ist.uwaterloo.ca/~schepers/formats/LHA.TXT
https://sites.google.com/site/pinczakko/pinczakko-s-guide-to-award-bios-reverse-engineering
"""

print('Award BIOS Module Extractor v1.0\n')

import os
import re
import sys
import subprocess

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	awd_images = sys.argv[1:]
else :
	# Folder path
	awd_images = []
	in_path = input('\nEnter the full folder path: ')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			awd_images.append(os.path.join(root, name))

pat_lzh = re.compile(br'\x2D\x6C((\x68(([\x30-\x37])|(\x64)))|(\x7A([\x34\x73])))\x2D') # All 11 LZH Method IDs (Award probably used LH0 and LH5 only)

# Create output folder
extr_path = os.path.join(os.getcwd(), 'AWD_Extracted')
if not os.path.exists(extr_path) : os.makedirs(extr_path)

for in_file in awd_images :
	file_path = os.path.abspath(in_file)
	file_name = os.path.basename(in_file)
	file_dir = os.path.dirname(file_path)
	file_ext = os.path.splitext(file_path)[1]
	match_lzh_list = []

	with open(in_file, 'rb') as awd_img : buffer = awd_img.read()
	
	match_lzh_list += pat_lzh.finditer(buffer) # Detect LZH patterns
			
	for match_lzh in match_lzh_list :
		hdr_size = buffer[match_lzh.start() - 0x2] # From LZH Tag (0x2+)
		comp_size = int.from_bytes(buffer[match_lzh.end():match_lzh.end() + 0x4], 'little') # From LZH Header end
		mod_data = buffer[match_lzh.start() - 0x2:match_lzh.start() + hdr_size + comp_size]
		
		with open('mod_temp.bin', 'wb') as lzh_img : lzh_img.write(mod_data)
		
		try : decomp = subprocess.run(['7z', 'x', '-bso0', '-bse0', '-bsp0', '-o%s' % os.path.join(extr_path, file_name), 'mod_temp.bin']) # 7-Zip
		except : print('Error: Could not decompress LZH image at %s!\n' % file_name)
			
		os.remove('mod_temp.bin') # Remove temporary LZH image
			
input('Done!')