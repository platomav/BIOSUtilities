#!/usr/bin/env python3

"""
Apple EFI Split
Apple EFI IM4P Splitter
Copyright (C) 2018 Plato Mavropoulos
"""

print('Apple EFI IM4P Splitter v1.2')

import os
import re
import sys

im4p = re.compile(br'\x16\x04\x49\x4D\x34\x50\x16\x04') # Apple IM4P
ifd = re.compile(br'\x5A\xA5\xF0\x0F.{172}\xFF{16}', re.DOTALL) # Intel Flash Descriptor

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	apple_im4p = sys.argv[1:]
else :
	# Folder path
	apple_im4p = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			apple_im4p.append(os.path.join(root, name))

for input_file in apple_im4p :
	file_path = os.path.abspath(input_file)
	file_name = os.path.basename(input_file)
	file_dir = os.path.dirname(file_path)
	file_ext = os.path.splitext(file_path)[1]
	
	print('\nFile: %s%s' % (file_name, file_ext))
	
	# Must be IM4P file because its size is 0x0 dependent
	if file_ext not in ('.im4p','.IM4P') :
		print('\n      Error: Could not find IM4P file extension at %s!' % file_name)
		continue
	
	with open(input_file, 'rb') as in_file : buffer = in_file.read()
	
	is_im4p = im4p.search(buffer) # Detect IM4P pattern
	
	if not is_im4p :
		print('\n      Error: Could not find IM4P pattern at %s!' % file_name)
		continue
	
	im4p_size = int.from_bytes(buffer[2:is_im4p.start()], 'big') # Variable, from 0x2 - IM4P
	im4p_type = buffer[is_im4p.end():is_im4p.end() + 0x4].decode('utf-8') # mefi
	
	if im4p_type != 'mefi' :
		print('\n      Error: Could not find "mefi" IM4P Type at %s!' % file_name)
		continue
	
	payload_start = is_im4p.start() + buffer[is_im4p.start() - 0x1]
	payload_size = int.from_bytes(buffer[is_im4p.end() + 0x9:is_im4p.end() + 0xD], 'big')
	
	ifd_count = list(ifd.finditer(buffer)) # Count the Intel FD(s) to determine each SPI size and offset
	
	# After IM4P mefi (0x15), multi SPI payloads have _MEFIBIN (0x100, difficult to reverse without varying samples)
	spi_start = payload_start + 0x100 if buffer[payload_start:payload_start + 0x8] == b'_MEFIBIN' else payload_start
	
	spi_size = int(len(buffer[spi_start:]) / len(ifd_count)) # Each SPI should be of the same size (1st PRD, 2nd PRE)
	
	# Parse all Intel FD and extract each SPI image
	for fd in range(len(ifd_count)) :
		file_path_new = os.path.join(file_dir, '%s_%d.fd' % (file_name[:-5], fd + 1))
		
		with open(file_path_new, 'wb') as spi_image : spi_image.write(buffer[spi_start:spi_start + spi_size])
		
		spi_start += spi_size
		
input('\nDone!')