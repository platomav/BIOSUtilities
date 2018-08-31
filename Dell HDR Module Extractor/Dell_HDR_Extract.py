#!/usr/bin/env python3

"""
Dell HDR Extract
Dell HDR Module Extractor
Copyright (C) 2018 Plato Mavropoulos
Inspired from https://forums.mydigitallife.net/threads/i-present-you-a-tool-to-decompress-dell-uefi-bios.44785/ by JimboBobB
"""

print('Dell HDR Module Extractor v1.0\n')

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
	for root, dirs, files in os.walk(in_path):
		for name in files :
			hdr_exec.append(os.path.join(root, name))

for input_file in hdr_exec :
	input_name,input_extension = os.path.splitext(os.path.basename(input_file))
	
	print('\nFile: %s%s' % (input_name, input_extension))
	
	with open(input_file, 'rb') as in_file : bios_data = in_file.read()
	
	# Compressed Dell HDR pattern followed by the zlib header of 0x789C
	pat_hdr = re.compile(br'\xAA\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78\x9C', re.DOTALL)
	match_hdr = pat_hdr.search(bios_data)
	
	# Check if Compressed Dell HDR pattern was found
	if not match_hdr :
		print('\n      Error: No Dell HDR found at %s%s!' % (input_name, input_extension))
		
		continue # Next input file
	
	# Detected Compressed Dell HDR pattern
	while match_hdr :
		# Store the compressed zlib data size from the proceeding 4 bytes of the Dell HDR pattern
		compressed_size = int.from_bytes(bios_data[match_hdr.start() - 0x4:match_hdr.start()], 'little')
		
		# Store compressed zlib data
		compressed_data  = bios_data[match_hdr.start() + 0xC:match_hdr.start() + 0xC + compressed_size]
		
		# Decompress zlib payload
		bios_data = zlib.decompress(compressed_data)
		
		# Scan for nested zlib data streams
		match_hdr = pat_hdr.search(bios_data)
	else :
		output_name = input_name + '.hdr'
		
		with open(output_name, 'wb') as hdr_file : hdr_file.write(bios_data)
		
		print('\n      Decompressed %s%s via Python' % (input_name, input_extension))
		
		# Call LongSoft's PFSExtractor RS to extract the Dell HDR container
		try :
			subprocess.run(['PFSExtractor', output_name], check = True, stdout = subprocess.DEVNULL)
			
			if os.path.isfile(output_name) : os.remove(output_name)
			
			print('      Extracted %s via PFSExtractor' % output_name)
		except :
			print('      Error: Could not extract %s via PFSExtractor!' % output_name)

else :
	input('\nDone!')