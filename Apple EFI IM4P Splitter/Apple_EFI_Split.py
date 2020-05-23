#!/usr/bin/env python3

"""
Apple EFI Split
Apple EFI IM4P Splitter
Copyright (C) 2018-2020 Plato Mavropoulos
"""

title = 'Apple EFI IM4P Splitter v2.0'

import os
import re
import sys

im4p = re.compile(br'\x16\x04\x49\x4D\x34\x50\x16\x04') # Apple IM4P
ifd = re.compile(br'\x5A\xA5\xF0\x0F.{172}\xFF{16}', re.DOTALL) # Intel Flash Descriptor (Z¥π. + [0xAC] + 0xFF * 16)

# Flash Descriptor Component Sizes
comp_dict = {
			0 : 0x80000, # 512 KB
			1 : 0x100000, # 1 MB
			2 : 0x200000, # 2 MB
			3 : 0x400000, # 4 MB
			4 : 0x800000, # 8 MB
			5 : 0x1000000, # 16 MB
			6 : 0x2000000, # 32 MB
			7 : 0x4000000, # 64 MB
			8 : 0x8000000, # 128 MB
			9 : 0x10000000, # 256 MB
			}

# Get input catalog file paths
if len(sys.argv) >= 3 and sys.argv[1] == '-skip' :
	# Called via Apple_EFI_Package
	apple_im4p = sys.argv[2:]
	skip_pause = True
	skip_space = '    '
	print('\n%s%s' % (skip_space, title)) # Print Title
elif len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	apple_im4p = sys.argv[1:]
	skip_pause = False
	skip_space = ''
	print('\n%s%s' % (skip_space, title)) # Print Title
else :
	# Folder path
	apple_im4p = []
	skip_pause = False
	skip_space = ''
	print('\n%s%s' % (skip_space, title)) # Print Title
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
	
	print('\n%sFile: %s' % (skip_space, file_name)) # Print File Name
	
	# Must be IM4P file because its size is 0x0 dependent
	if file_ext not in ('.im4p','.IM4P') :
		print('\n%s      Error: Could not find IM4P file extension at %s!' % (skip_space, file_name))
		continue # Critical error
	
	with open(input_file, 'rb') as in_file : buffer = in_file.read()
	
	is_im4p = im4p.search(buffer) # Detect IM4P pattern
	
	if not is_im4p :
		print('\n%s      Error: Could not find IM4P pattern at %s!' % (skip_space, file_name))
		continue # Critical error
	
	im4p_size = int.from_bytes(buffer[2:is_im4p.start()], 'big') # Variable, from 0x2 - IM4P
	im4p_type = buffer[is_im4p.end():is_im4p.end() + 0x4].decode('utf-8') # mefi
	
	if im4p_type != 'mefi' :
		print('\n%s      Error: Could not find "mefi" IM4P Type at %s!' % (skip_space, file_name))
		continue # Critical error
	
	# After IM4P mefi (0x15), multi EFI payloads have _MEFIBIN (0x100) which is difficult to reverse without varying samples.
	# However, _MEFIBIN is not required for splitting SPI/EFI images because Intel Flash Descriptor Component Density exists.
	mefi_data_start = is_im4p.start() + buffer[is_im4p.start() - 0x1] # IM4P mefi payload start offset
	mefi_data_size = int.from_bytes(buffer[is_im4p.end() + 0x9:is_im4p.end() + 0xD], 'big') # IM4P mefi payload size
	mefibin_exist = buffer[mefi_data_start:mefi_data_start + 0x8] == b'_MEFIBIN' # Check if mefi is followed by _MEFIBIN
	efi_data_start = mefi_data_start + 0x100 if mefibin_exist else mefi_data_start # Actual multi EFI payloads start after _MEFIBIN
	efi_data_size = mefi_data_size - 0x100 if mefibin_exist else mefi_data_size # Actual multi EFI payloads size without _MEFIBIN
	buffer = buffer[efi_data_start:efi_data_start + efi_data_size] # Adjust input file buffer to actual multi EFI payloads data
	
	fd_matches = list(ifd.finditer(buffer)) # Find Intel Flash Descriptor pattern matches
	fd_count = len(fd_matches) # Count found Intel Flash Descriptor pattern matches
	fd_final = [] # Initialize final Intel Flash Descriptor info storage
	
	# Parse Intel Flash Descriptor pattern matches
	for fd_idx in range(fd_count) :
		fd = fd_matches[fd_idx] # Get Intel Flash Descriptor match object
		
		# Platform Controller Hub (PCH)
		if (fd.start() == 0x10 or buffer[fd.start() - 0x4:fd.start()] == b'\xFF' * 4) \
		and buffer[fd.start() + 0x4] in [3,2] and buffer[fd.start() + 0x6] == 4 :
			start_substruct = 0x10 # At PCH, Flash Descriptor starts at 0x10
			end_substruct = 0xBC # 0xBC for [0xAC] + 0xFF * 16 sanity check
		# I/O Controller Hub (ICH)
		else :
			start_substruct = 0x0 # At ICH, Flash Descriptor starts at 0x0
			end_substruct = 0xBC # 0xBC for [0xAC] + 0xFF * 16 sanity check
			
		fd_match_start = fd.start() - start_substruct # Actual Flash Descriptor Start Offset
		fd_match_end = fd.end() - end_substruct # Actual Flash Descriptor End Offset
		
		# Calculate Intel Flash Descriptor Flash Component Total Size
		fd_flmap0_nc = ((int.from_bytes(buffer[fd_match_end:fd_match_end + 0x4], 'little') >> 8) & 3) + 1 # Component Count (00 = 1, 01 = 2)
		fd_flmap1_isl = buffer[fd_match_end + 0x7] # PCH Strap Length (ICH8-IBX <= 0x10, CPT-PPT = 0x12, LPT+ >= 0x15)
		fd_comp_den_off = 0x1C if fd_flmap1_isl > 0x10 else 0xC # Component Density Offset (ICH8-IBX = 0xC, CPT+ = 0x1C)
		fd_comp_den_byte = buffer[fd_match_end + fd_comp_den_off] # Component Density Byte (ICH8-PPT = 0:5, LPT+ = 0:7)
		fd_comp_1_bitwise = 0xF if fd_flmap1_isl >= 0x15 else 0x7 # Component 1 Density Bits (ICH8-PPT = 3, LPT+ = 4)
		fd_comp_2_bitwise = 0x4 if fd_flmap1_isl >= 0x15 else 0x3 # Component 2 Density Bits (ICH8-PPT = 3, LPT+ = 4)
		fd_comp_all_size = comp_dict[fd_comp_den_byte & fd_comp_1_bitwise] # Component 1 Density (FCBA > C0DEN)
		if fd_flmap0_nc == 2 : fd_comp_all_size += comp_dict[fd_comp_den_byte >> fd_comp_2_bitwise] # Component 2 Density (FCBA > C1DEN)
		
		fd_final.append((fd_match_start,fd_comp_all_size)) # Store Intel Flash Descriptor final info
	
	# Split IM4P via the final Intel Flash Descriptor mathes
	for fd_idx in range(fd_count) :
		fd = fd_final[fd_idx] # Get Intel Flash Descriptor final info [FD Start, FD Component(s) Size]
		
		# The Intel Flash Descriptor Flash Component Total Size should be enough to split the IM4P.
		# However, for sanity, its Size can be compared to the Size different of Next - Current FD.
		fd_diff_size = len(buffer) - fd[0] if fd_idx == fd_count - 1 else fd_final[fd_idx + 1][0] - fd[0] # Last FD ends at mefi payload end
		if fd[1] != fd_diff_size : # FD Total Component Size should be equal to Next-Current FD Difference Size
			print('\n%s      Error: Intel FD %d/%d Component Size 0x%X != Next-Current FD Size Difference 0x%X!'
				  % (skip_space, fd_idx + 1, fd_count, fd[1], fd_diff_size))
		
		file_data = buffer[fd[0]:fd[0] + max(fd[1], fd_diff_size)] # Split EFI image file data (use largest FD Size just in case)
		
		file_path_new = os.path.join(file_dir, '%s_%d.fd' % (file_name[:-5], fd_idx + 1)) # Split EFI image file path
		
		with open(file_path_new, 'wb') as spi_image : spi_image.write(file_data) # Store split EFI image file
		
	print('\n%s      Split IM4P into %d EFI image(s)!' % (skip_space, fd_count))
		
if not skip_pause : input('\nDone!')