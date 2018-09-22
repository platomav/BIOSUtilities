#!/usr/bin/env python3

"""
Dell HDR Extract
Dell HDR Module Extractor
Copyright (C) 2018 Plato Mavropoulos
Inspired from https://forums.mydigitallife.net/threads/i-present-you-a-tool-to-decompress-dell-uefi-bios.44785/ by JimboBobB
"""

print('Dell HDR Module Extractor v2.0\n')

import os
import re
import sys
import zlib
import subprocess

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	hdr_exec = sys.argv[1:]
else :
	# Folder path
	hdr_exec = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			hdr_exec.append(os.path.join(root, name))

for input_file in hdr_exec :
	input_name,input_extension = os.path.splitext(os.path.basename(input_file))
	
	print('\nFile: %s%s' % (input_name, input_extension))
	
	with open(input_file, 'rb') as in_file : bios_data = in_file.read()
	
	# Compressed Dell HDR pattern followed by the zlib header of 0x789C
	match_hdr = re.compile(br'\xAA\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78\x9C', re.DOTALL).search(bios_data)
	
	# Check if compressed Dell HDR pattern was found
	if not match_hdr :
		print('\n      Error: No Dell HDR found at %s%s!' % (input_name, input_extension))
		continue # Next input file
	
	# Store the compressed zlib data size from the proceeding 4 bytes of the Dell HDR pattern
	compressed_size = int.from_bytes(bios_data[match_hdr.start() - 0x4:match_hdr.start()], 'little')
	
	# Decompress zlib payload from 0x789C via Python
	decomp_data = zlib.decompress(bios_data[match_hdr.start() + 0xC:match_hdr.start() + 0xC + compressed_size])
	
	output_name = input_name + '.hdr'
	
	with open(output_name, 'wb') as hdr_file : hdr_file.write(decomp_data)
	
	print('\n      Decompressed %s%s via Python' % (input_name, input_extension))
	
	# Extract the Dell HDR image via LongSoft's PFSExtractor-RS
	try :
		subprocess.run(['PFSExtractor', output_name], check = True, stdout = subprocess.DEVNULL)
		
		if os.path.isfile(output_name) : os.remove(output_name)
		
		print('      Extracted %s via PFSExtractor-RS' % output_name)
	except :
		print('      Error: Could not extract %s via PFSExtractor-RS!' % output_name)
		print('             Make sure that "PFSExtractor" executable exists!')

else :
	input('\nDone!')