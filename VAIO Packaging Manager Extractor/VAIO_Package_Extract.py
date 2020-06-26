#!/usr/bin/env python3

"""
VAIO Package Extractor
VAIO Packaging Manager Extractor
Copyright (C) 2019-2020 Plato Mavropoulos
"""

print('VAIO Packaging Manager Extractor v2.0')

import os
import re
import sys
import subprocess

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	vaio_exec = sys.argv[1:]
else :
	# Folder path
	vaio_exec = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			vaio_exec.append(os.path.join(root, name))

# Microsoft CAB Header XOR 0xFF (Tag[4] + Res[4] + Size[4] + Res[4] + Offset[4] + Res[4] + Ver[2]) pattern
mscf_pattern = re.compile(br'\xB2\xAC\xBC\xB9\xFF{4}.{4}\xFF{4}.{4}\xFF{4}\xFC\xFE', re.DOTALL)

# VAIO Packaging Manager Configuration file ("[Setting]" + Windows_new_line) pattern
vaio_pattern = re.compile(br'\x5B\x53\x65\x74\x74\x69\x6E\x67\x5D\x0D\x0A')

# VAIO Packaging Manager Configuration file entry "UseVAIOCheck" pattern
check_pattern = re.compile(br'\x0A\x55\x73\x65\x56\x41\x49\x4F\x43\x68\x65\x63\x6B\x3D')

# VAIO Packaging Manager Configuration file entry "ExtractPathByUser" pattern
path_pattern = re.compile(br'\x0A\x45\x78\x74\x72\x61\x63\x74\x50\x61\x74\x68\x42\x79\x55\x73\x65\x72\x3D')

for input_file in vaio_exec :
	file_path = os.path.abspath(input_file)
	file_dir = os.path.dirname(file_path)
	file_name = os.path.basename(file_path)
	
	print('\nFile: ' + file_name)
	
	# Open Locked VAIO Packaging Manager executable as mutable bytearray
	with open(input_file, 'rb') as in_file : vaio_data = bytearray(in_file.read())
	
	match_mscf = mscf_pattern.search(vaio_data) # Search for Microsoft CAB Header XOR 0xFF pattern
	
	match_vaio = vaio_pattern.search(vaio_data) if not match_mscf else None # Search for VAIO Packaging Manager Configuration file
	
	# Check if Microsoft CAB Header XOR 0xFF pattern exists
	if match_mscf :
		print('\n      Detected Obfuscation!')
		
		# Determine the Microsoft CAB image Size
		cab_size = int.from_bytes(vaio_data[match_mscf.start() + 0x8:match_mscf.start() + 0xC], 'little') # Get LE XOR-ed CAB Size
		xor_size = int.from_bytes(b'\xFF' * 0x4, 'little') # Create CAB Size XOR value
		cab_size = cab_size ^ xor_size # Perform XOR 0xFF and get actual CAB Size
		
		print('\n      Removing Obfuscation...')
		
		# Determine the Microsoft CAB image Data
		cab_data = int.from_bytes(vaio_data[match_mscf.start():match_mscf.start() + cab_size], 'big') # Get BE XOR-ed CAB Data
		xor_data = int.from_bytes(b'\xFF' * cab_size, 'big') # Create CAB Data XOR value
		cab_data = (cab_data ^ xor_data).to_bytes(cab_size, 'big') # Perform XOR 0xFF and get actual CAB Data
		
		print('\n      Extracting...')
		
		with open('vaio_temp.cab', 'wb') as cab_file : cab_file.write(cab_data) # Create temporary CAB image
		
		extr_path = os.path.join(file_dir, file_name[:-4], '') # Create CAB image extraction path
		
		try :
			decomp = subprocess.run(['7z', 'x', '-aou', '-bso0', '-bse0', '-bsp0', '-o' + extr_path, 'vaio_temp.cab']) # 7-Zip
			
			print('\n      Extracted!')
		except :
			print('\n      Error: Could not decompress Microsoft CAB image!')
			print('             Make sure that "7z" executable exists!')
			
		os.remove('vaio_temp.cab') # Remove temporary CAB image
	
	# Check if VAIO Packaging Manager Configuration file pattern exists
	elif match_vaio :
		print('\n      Error: Failed to Extract, attempting to Unlock instead...')
		
		# Initialize VAIO Package Configuration file variables (assume overkill size of 0x500)
		info_start, info_end, val_false, val_true = [match_vaio.start(), match_vaio.start() + 0x500, b'', b'']
		
		# Get VAIO Package Configuration file info, split at new_line and stop at payload DOS header (EOF)
		vaio_info = vaio_data[info_start:info_end].split(b'\x0D\x0A\x4D\x5A')[0].replace(b'\x0D',b'').split(b'\x0A')
		
		# Determine VAIO Package Configuration file True & False values
		for info in vaio_info :
			if info.startswith(b'ExtractPathByUser=') : val_false = bytearray(b'0' if info[18:] in (b'0',b'1') else info[18:]) # Should be 0/No/False
			if info.startswith(b'UseCompression=') : val_true = bytearray(b'1' if info[15:] in (b'0',b'1') else info[15:]) # Should be 1/Yes/True
		else :
			if val_false == val_true or not val_false or not val_true :
				print('\n      Error: Could not determine True/False values!')
				print('             Please report this VAIO Packaging Manager!')
				continue # Next input file
		
		# Find and replace UseVAIOCheck entry from 1/Yes/True to 0/No/False
		UseVAIOCheck = check_pattern.search(vaio_data[info_start:])
		if UseVAIOCheck : vaio_data[info_start + UseVAIOCheck.end():info_start + UseVAIOCheck.end() + len(val_false)] = val_false
		else : print('\n      Error: Could not find UseVAIOCheck entry!')
		
		# Find and replace ExtractPathByUser entry from 0/No/False to 1/Yes/True
		ExtractPathByUser = path_pattern.search(vaio_data[info_start:])
		if ExtractPathByUser : vaio_data[info_start + ExtractPathByUser.end():info_start + ExtractPathByUser.end() + len(val_false)] = val_true
		else : print('\n      Error: Could not find ExtractPathByUser entry!')
		
		# Store Unlocked VAIO Packaging Manager executable
		if UseVAIOCheck and ExtractPathByUser :
			with open(os.path.join(file_dir, file_name + '_Unlocked.exe'), 'wb') as unl_file : unl_file.write(vaio_data)
			print('\n      Unlocked!')
		
	else :
		print('\n      Error: No VAIO Packaging Manager found!')
		continue # Next input file

else :
	input('\nDone!')