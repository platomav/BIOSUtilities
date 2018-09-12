#!/usr/bin/env python3

"""
Panasonic BIOS Extract
Panasonic BIOS Update Extractor
Copyright (C) 2018 Plato Mavropoulos
"""

print('Panasonic BIOS Update Extractor v1.0')

import os
import sys
import shutil
import pefile
import subprocess

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	panasonic = sys.argv[1:]
else :
	# Folder path
	panasonic = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			panasonic.append(os.path.join(root, name))

for input_file in panasonic :
	file_path = os.path.abspath(input_file)
	file_name = os.path.basename(input_file)
	file_dir = os.path.dirname(file_path)
	file_ext = os.path.splitext(file_path)[1]
	
	# Create output folder
	extr_path = os.path.join(os.getcwd(), 'RCDATA')
	if os.path.exists(extr_path) : shutil.rmtree(extr_path)
	os.makedirs(extr_path)
	
	max_size = 0
	max_file = None
	pe = pefile.PE(input_file) # Analyze Portable Executable (PE)
	for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries :
		# Parse Resource Data directories only
		if entry.struct.name == 'IMAGE_RESOURCE_DIRECTORY_ENTRY' and entry.struct.Id == 10 : # RCDATA ID = 10
			for resource in entry.directory.entries :
				offset = resource.directory.entries[0].data.struct.OffsetToData
				size = resource.directory.entries[0].data.struct.Size
				data = pe.get_data(offset, size)
				file = os.path.join(extr_path, '%X_%X.bin' % (offset, size))
				with open(file, 'wb') as out_file : out_file.write(data)
				
				# Remember largest resource (SPI/BIOS)
				if size > max_size :
					max_size = size
					max_file = file
	
	if not max_file :
		print('\nError: No Panasonic BIOS Update at %s!' % file_name)
		shutil.rmtree(extr_path) # Remove temporary folder
		continue # Next input file
	
	# Call Rustam Abdullaev's unpack_lznt1 to extract the LZNT1-compressed SPI/BIOS resource at 0x8 onwards
	try :
		subprocess.run(['unpack_lznt1', max_file, os.path.join(file_dir, file_name[:-4] + '.bin'), '8'], check = True, stdout = subprocess.DEVNULL)
		print('\nExtracted %s via unpack_lznt1' % (file_name[:-4] + '.bin'))
	except :
		print('\nError: Could not extract %s via unpack_lznt1!' % (file_name[:-4] + '.bin'))
		print('       Make sure that "unpack_lznt1.exe" executable exists!')
		
	shutil.rmtree(extr_path) # Remove temporary folder

else :
	input('\nDone!')