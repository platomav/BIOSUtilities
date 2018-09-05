#!/usr/bin/env python3

"""
Apple EFI Rename
Apple EFI File Renamer
Copyright (C) 2018 Plato Mavropoulos
https://github.com/tianocore/edk2/blob/master/Vlv2TbltDevicePkg/Include/Library/BiosIdLib.h
"""

print('Apple EFI File Renamer v1.2\n')

import os
import re
import sys
import zlib
import shutil
import subprocess

pattern = re.compile(br'\x24\x49\x42\x49\x4F\x53\x49\x24') # Intel $IBIOSI$

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	apple_efi = sys.argv[1:]
else :
	# Folder path
	apple_efi = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...\n')
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
		
		bios_info = buffer[is_ibiosi.end():is_ibiosi.end() + 0x42].decode('utf-16')
		
		BoardID = bios_info[:7].strip()
		BoardRev = bios_info[7]
		OEMID = bios_info[9:12] # 88Z
		MajorVer = bios_info[13:17]
		BuildType = bios_info[18] # B
		MinorVer = bios_info[19:21]
		Year = bios_info[22:24]
		Month = bios_info[24:26]
		Day = bios_info[26:28]
		Hour = bios_info[28:30]
		Minute = bios_info[30:32]
		
		file_chk = zlib.adler32(buffer) # Checksum for EFI with same $IBIOSI$ but different PRD/PRE status
		
		new_name = '%s%s_%s_%s%s_20%s-%s-%s_%s-%s_%0.8X%s' % (BoardID, BoardRev, MajorVer, BuildType, MinorVer, Year, Month, Day, Hour, Minute, file_chk, file_ext)
		
		file_path_new = os.path.join(file_dir, new_name)
		
		if not os.path.isfile(file_path_new) : os.replace(file_path, file_path_new) # Rename input EFI with proper name
		
		print(new_name)
		print('\nBoard Identity: %s%s' % (BoardID, BoardRev))
		print('Apple Identity: %s' % OEMID)
		print('Major Version:  %s' % MajorVer)
		print('Minor Version:  %s' % MinorVer)
		print('Build Type:     %s' % BuildType)
		print('Build Date:     20%s-%s-%s' % (Year, Month, Day))
		print('Build Time:     %s:%s\n' % (Hour, Minute))
		
	else :
		print('\nError: Could not find $IBIOSI$ pattern at %s!' % file_name)
		print('       Make sure that "UEFIFind" and "UEFIExtract" executables exist!\n')
		
input('Done!')