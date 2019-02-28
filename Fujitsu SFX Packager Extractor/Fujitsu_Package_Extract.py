#!/usr/bin/env python3

"""
Fujitsu Package Extractor
Fujitsu SFX Packager Extractor
Copyright (C) 2019 Plato Mavropoulos
"""

print('Fujitsu SFX Packager Extractor v1.0')

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
		print('\n      Detected obfuscated Microsoft CAB image.')
		
		mscf_start = match_mscf.start() + 0xA # Microsoft CAB Header XOR 0xFF starts after "FjSfxBinay" signature
		
		# Determine the Microsoft CAB image Size
		cab_size_hex = bytearray(4) # Initialize LE Hex CAB Size as mutable bytearray
		cab_size_xor = FjSfx[mscf_start + 0x8:mscf_start + 0xC] # Get LE XOR-ed CAB Size
		for idx in range(4) : # Parse each CAB Size byte
			cab_size_hex[idx] = cab_size_xor[idx] ^ 0xFF # Perform XOR 0xFF
		cab_size = int.from_bytes(cab_size_hex, 'little') # Get BE Actual CAB Size
		
		print('\n      Removing Obfuscation...') # May take a while
		
		# Determine the Microsoft CAB image Data
		cab_data = bytearray(cab_size) # Initialize CAB Data as mutable bytearray
		cab_data_xor = FjSfx[mscf_start:mscf_start + cab_size] # Get XOR-ed CAB Data
		for idx in range(cab_size) : # Parse each CAB Data byte
			cab_data[idx] = cab_data_xor[idx] ^ 0xFF # Perform XOR 0xFF and get Actual CAB Data
		
		print('\n      Extracting...')
		
		with open('fjsfx_temp.cab', 'wb') as cab_file : cab_file.write(cab_data) # Create temporary CAB image
		
		extr_path = os.path.join(file_dir, file_name[:-4], '') # Create CAB image extraction path
		
		try :
			decomp = subprocess.run(['7z', 'x', '-aou', '-bso0', '-bse0', '-bsp0', '-o' + extr_path, 'fjsfx_temp.cab']) # 7-Zip
		except :
			print('\n      Error: Could not decompress Microsoft CAB image!')
			print('               Make sure that "7z" executable exists!\n')
			
		os.remove('fjsfx_temp.cab') # Remove temporary CAB image
		
		print('\n      Extracted!')
		
	else :
		print('\n      Error: No Fujitsu SFX Packager found!')
		continue # Next input file

else :
	input('\nDone!')