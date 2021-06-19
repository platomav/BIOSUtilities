#!/usr/bin/env python3
#coding=utf-8

"""
Portwell EFI Extract
Portwell EFI BIOS Extractor
Copyright (C) 2021 Plato Mavropoulos
"""

title = 'Portwell EFI BIOS Extractor v1.0'

print('\n' + title) # Print script title

import sys

# Detect Python version
sys_ver = sys.version_info
if sys_ver < (3,7) :
	sys.stdout.write('\n\nError: Python >= 3.7 required, not %d.%d!\n' % (sys_ver[0], sys_ver[1]))
	(raw_input if sys_ver[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
	sys.exit(1)

import os
import pefile
import shutil
import ctypes
import argparse
import traceback
import subprocess

# Pause after any unexpected Python exception
# https://stackoverflow.com/a/781074 by Torsten Marek
def show_exception_and_exit(exc_type, exc_value, tb) :
	if exc_type is KeyboardInterrupt :
		print('\n')
	else :
		print('\nError: %s crashed, please report the following:\n' % title)
		traceback.print_exception(exc_type, exc_value, tb)
		input('\nPress enter to exit')
	
	sys.exit(1)

# Set pause-able Python exception handler
sys.excepthook = show_exception_and_exit

# Set console/shell window title
user_os = sys.platform
if user_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(title)
elif user_os.startswith('linux') or user_os == 'darwin' or user_os.find('bsd') != -1 : sys.stdout.write('\x1b]2;' + title + '\x07')

# Set argparse Arguments
efi_parser = argparse.ArgumentParser()
efi_parser.add_argument('efi', type=argparse.FileType('r'), nargs='*')
efi_parser.add_argument('-p', '--path', help='parse files within given folder', type=str)
efi_params = efi_parser.parse_args()

# Get all files within path
def get_files(path) :
	inputs = []
	
	for root, _, files in os.walk(path):
		for name in files :
			inputs.append(os.path.join(root, name))
	
	return inputs

if len(sys.argv) >= 2 :
	if bool(efi_params.path) :
		efi_exec = get_files(efi_params.path) # CLI with --path
	else :
		efi_exec = []
		for executable in efi_params.efi :
			efi_exec.append(executable.name) # Drag & Drop
else :
	in_path = input('\nEnter the full folder path: ')
	efi_exec = get_files(in_path) # Direct Run

# Portwell UEFI Unpacker File Names (v1.1 - v1.2)
file_names = {0 : 'Flash.efi', 1 : 'Fparts.txt', 2 : 'Update.nsh', 3 : 'Temp.bin', 4 : 'SaveDmiData.efi'}

# Process each input Portwell EFI Update Package
for input_file in efi_exec :
	input_name,input_extension = os.path.splitext(os.path.basename(input_file))
	input_dir = os.path.dirname(os.path.abspath(input_file))
	
	print('\n*** %s%s' % (input_name, input_extension))
	
	# Check if input file exists
	if not os.path.isfile(input_file) :
		print('\n    Error: This input file does not exist!')
		continue # Next input file
	
	with open(input_file, 'rb') as in_file : input_data = in_file.read()
	
	try :
		assert input_data[0x0:0x2] == b'\x4D\x5A' # EFI images start with DOS Header MZ
		
		pe = pefile.PE(input_file, fast_load=True) # Analyze EFI Portable Executable (PE)
		
		payload_data = input_data[pe.OPTIONAL_HEADER.SizeOfImage:] # Skip EFI executable (pylint: disable=E1101)
		
		assert payload_data[0x0:0x4] == b'\x3C\x55\x55\x3E' # Portwell EFI files start with <UU>
	except :
		print('\n    Error: This is not a Portwell EFI Update Package!')
		continue # Next input file
	
	output_path = os.path.join(input_dir, '%s%s' % (input_name, input_extension) + '_extracted') # Set extraction directory
	
	if os.path.isdir(output_path) : shutil.rmtree(output_path) # Delete any existing extraction directory
	
	os.mkdir(output_path) # Create extraction directory
	
	pack_tag = 'UEFI Unpacker' # Initialize Portwell UEFI Unpacker tag
	
	# Get Portwell UEFI Unpacker tag
	for s in pe.sections :
		if s.Name.startswith(b'.data') : # Unpacker Tag, Version, Strings etc are found in .data PE section
			# Decode any valid UTF-16 .data PE section info to a parsable text buffer
			info = input_data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData].decode('utf-16','ignore')
			
			# Search .data for UEFI Unpacker tag
			pack_tag_off = info.find('UEFI Unpacker')
			if pack_tag_off != -1 :
				pack_tag_len = info[pack_tag_off:].find('=')
				if pack_tag_len != -1 :
					# Found full UEFI Unpacker tag, store and slightly beautify the resulting text
					pack_tag = info[pack_tag_off:pack_tag_off + pack_tag_len].strip().replace('   ',' ').replace('<',' <')
			
			break # Found PE .data section, skip the rest
	
	print('\n    Portwell %s' % pack_tag) # Print Portwell UEFI Unpacker tag
	
	efi_files = payload_data.split(b'\x3C\x55\x55\x3E')[1:] # Split EFI Payload into <UU> file chunks
	
	# Parse each EFI Payload File
	for i in range(len(efi_files)) :
		file_data = efi_files[i] # Store EFI File data
		
		if len(file_data) == 0 or file_data == b'NULL' : continue # Skip empty/unused files
		
		is_known = i in file_names # Check if EFI file is known & Store result
		
		file_name = file_names[i] if is_known else 'Unknown_%d.bin' % i # Assign Name to EFI file
		
		print('\n        %s' % file_name) # Print EFI file name, indicate progress
		
		if not is_known : input('\n            Note: Detected unknown Portwell EFI file with ID %d!' % i) # Report new EFI files
		
		file_path = os.path.join(output_path, file_name) # Store EFI file output path
		
		with open(file_path, 'wb') as o : o.write(file_data) # Store EFI file data to drive
		
		# Attempt to detect EFI/Tiano Compression & Decompress when applicable
		if int.from_bytes(file_data[0x0:0x4], 'little') + 0x8 == len(file_data) :
			try :
				comp_fname = file_path + '.temp' # Store temporary compressed file name
				
				os.replace(file_path, comp_fname) # Rename initial/compressed file
				
				subprocess.run(['TianoCompress', '-d', comp_fname, '-o', file_path, '--uefi', '-q'], check = True, stdout = subprocess.DEVNULL)
				
				if os.path.getsize(file_path) != int.from_bytes(file_data[0x4:0x8], 'little') : raise Exception('EFI_DECOMP_ERROR')
				
				os.remove(comp_fname) # Successful decompression, delete initial/compressed file
			
			except :
				print('\n            Error: Could not extract file %s via TianoCompress!' % file_name)
				input('                   Make sure that "TianoCompress" executable exists!')
	
	print('\n    Extracted Portwell EFI Update Package!')

input('\nDone!')

sys.exit(0)