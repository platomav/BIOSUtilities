#!/usr/bin/env python3

"""
Fujitsu Package Extractor
Fujitsu SFX Packager Extractor
Copyright (C) 2019-2020 Plato Mavropoulos
"""

print('Fujitsu SFX Packager Extractor v2.0')

import os
import re
import sys
import subprocess

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	fjsfx_exec = sys.argv[1:]
else :
	# Folder path
	fjsfx_exec = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			fjsfx_exec.append(os.path.join(root, name))

# "FjSfxBinay" + Microsoft CAB Header XOR 0xFF (Tag[4] + Res[4] + Size[4] + Res[4] + Offset[4] + Res[4] + Ver[2]) pattern
mscf_pattern = re.compile(br'\x46\x6A\x53\x66\x78\x42\x69\x6E\x61\x79\xB2\xAC\xBC\xB9\xFF{4}.{4}\xFF{4}.{4}\xFF{4}\xFC\xFE', re.DOTALL)
			
for input_file in fjsfx_exec :
	file_path = os.path.abspath(input_file)
	file_dir = os.path.dirname(file_path)
	file_name = os.path.basename(file_path)
	
	print('\nFile: ' + file_name)
	
	# Open Fujitsu SFX Binary Packager executable as mutable bytearray
	with open(input_file, 'rb') as in_file : FjSfx = bytearray(in_file.read())
	
	match_mscf = mscf_pattern.search(FjSfx) # Search for Fujitsu Microsoft CAB Header XOR 0xFF pattern
	
	# Check if Microsoft CAB Header XOR 0xFF pattern exists
	if match_mscf :
		print('\n      Detected Obfuscation!')
		
		mscf_start = match_mscf.start() + 0xA # Microsoft CAB Header XOR 0xFF starts after "FjSfxBinay" signature
		
		# Determine the Microsoft CAB image Size
		cab_size = int.from_bytes(FjSfx[mscf_start + 0x8:mscf_start + 0xC], 'little') # Get LE XOR-ed CAB Size
		xor_size = int.from_bytes(b'\xFF' * 0x4, 'little') # Create CAB Size XOR value
		cab_size = cab_size ^ xor_size # Perform XOR 0xFF and get actual CAB Size
		
		print('\n      Removing Obfuscation...')
			
		# Determine the Microsoft CAB image Data
		cab_data = int.from_bytes(FjSfx[mscf_start:mscf_start + cab_size], 'big') # Get BE XOR-ed CAB Data
		xor_data = int.from_bytes(b'\xFF' * cab_size, 'big') # Create CAB Data XOR value
		cab_data = (cab_data ^ xor_data).to_bytes(cab_size, 'big') # Perform XOR 0xFF and get actual CAB Data
		
		print('\n      Extracting...')
		
		with open('fjsfx_temp.cab', 'wb') as cab_file : cab_file.write(cab_data) # Create temporary CAB image
		
		extr_path = os.path.join(file_dir, file_name[:-4], '') # Create CAB image extraction path
		
		try :
			decomp = subprocess.run(['7z', 'x', '-aou', '-bso0', '-bse0', '-bsp0', '-o' + extr_path, 'fjsfx_temp.cab']) # 7-Zip
			
			print('\n      Extracted!')
		except :
			print('\n      Error: Could not decompress Microsoft CAB image!')
			print('             Make sure that "7z" executable exists!')
			
		os.remove('fjsfx_temp.cab') # Remove temporary CAB image
		
	else :
		print('\n      Error: No Fujitsu SFX Packager found!')
		continue # Next input file

else :
	input('\nDone!')