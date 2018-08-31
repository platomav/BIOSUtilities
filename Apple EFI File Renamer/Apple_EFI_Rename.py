#!/usr/bin/env python3

"""
Apple EFI Rename
Apple EFI File Renamer
Copyright (C) 2018 Plato Mavropoulos
"""

print('Apple EFI File Renamer v1.0\n')

import os
import re
import sys
import zlib
import shutil
import subprocess

pattern = re.compile(br'\x24\x49\x42\x49\x4F\x53\x49\x24') # Apple $IBIOSI$

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	apple_efi = sys.argv[1:]
else :
	# Folder path
	apple_efi = []
	in_path = input('\nEnter the full folder path: ')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			apple_efi.append(os.path.join(root, name))

for input_file in apple_efi :
	file_path = os.path.abspath(input_file)
	file_name = os.path.basename(input_file)
	file_dir = os.path.dirname(file_path)
	file_ext = os.path.splitext(file_path)[1]
	error = False
	
	with open(input_file, 'rb') as in_file : buffer = in_file.read()
	
	is_ibiosi = pattern.search(buffer) # Detect $IBIOSI$ pattern
	
	if not is_ibiosi :
		
		# On some Apple EFI, the $IBIOSI$ pattern is within compressed modules so we need to use UEFIFind and UEFIExtract
		
		try :
			uefifind = subprocess.check_output(['UEFIFind', file_path, 'body', 'list', '244942494F534924'], universal_newlines=True)
			uefiextr = subprocess.run(['UEFIExtract', file_path, uefifind[0:36], '-o', '_$IBIOSI$_', '-m', 'body'], stdout=subprocess.DEVNULL)
			
			with open(os.path.join('_$IBIOSI$_', 'body.bin'), 'rb') as in_file : buffer = in_file.read()
			
			is_ibiosi = pattern.search(buffer) # Detect decompressed $IBIOSI$ pattern
			
			shutil.rmtree('_$IBIOSI$_') # Remove temporary folder
			
		except :
			error = True

	if not error :
		
		bios_info = buffer[is_ibiosi.end():is_ibiosi.end() + 0x40].split(b'\x2E\x00') # Each $IBIOSI$ section ends with 0x2E00
		
		model = bios_info[0].decode('utf-16').strip()
		tag = bios_info[1].decode('utf-16').strip() # 88Z
		version = bios_info[2].decode('utf-16').strip()
		build = bios_info[3].decode('utf-16').strip() # Bxx
		datetime = bios_info[4].decode('utf-16').strip() # Year Month Day Hour Minute
		year = datetime[0:2]
		month = datetime[2:4]
		day = datetime[4:6]
		hour = datetime[6:8]
		minute = datetime[8:10]
		
		file_chk = zlib.adler32(buffer) & 0xFFFFFFFF # Checksum for EFI with same $IBIOSI$ but different PRD/PRE status
		
		file_path_new = os.path.join(file_dir, '%s_%s_%s_20%s-%s-%s_%s-%s_%s%s' % (model, version, build, year, month, day, hour, minute, file_chk, file_ext))
		
		if not os.path.isfile(file_path_new) : os.replace(file_path, file_path_new) # Rename input EFI with proper name
		
	else :
		print('Error: Could not find $IBIOSI$ pattern at %s!\n' % file_name)
		
input('Done!')