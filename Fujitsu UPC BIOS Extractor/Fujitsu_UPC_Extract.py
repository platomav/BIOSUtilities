#!/usr/bin/env python3
#coding=utf-8

"""
Fujitsu UPC Extract
Fujitsu UPC BIOS Extractor
Copyright (C) 2021 Plato Mavropoulos
"""

title = 'Fujitsu UPC BIOS Extractor v1.0'

print('\n' + title) # Print script title

import sys

# Detect Python version
sys_ver = sys.version_info
if sys_ver < (3,7) :
	sys.stdout.write('\n\nError: Python >= 3.7 required, not %d.%d!\n' % (sys_ver[0], sys_ver[1]))
	(raw_input if sys_ver[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
	sys.exit(1)

import os
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
upc_parser = argparse.ArgumentParser()
upc_parser.add_argument('upc', type=argparse.FileType('r'), nargs='*')
upc_parser.add_argument('-p', '--path', help='parse files within given folder', type=str)
upc_params = upc_parser.parse_args()

# Get all files within path
def get_files(path) :
	inputs = []
	
	for root, _, files in os.walk(path):
		for name in files :
			inputs.append(os.path.join(root, name))
	
	return inputs

if len(sys.argv) >= 2 :
	if bool(upc_params.path) :
		upc_exec = get_files(upc_params.path) # CLI with --path
	else :
		upc_exec = []
		for executable in upc_params.upc :
			upc_exec.append(executable.name) # Drag & Drop
else :
	in_path = input('\nEnter the full folder path: ')
	upc_exec = get_files(in_path) # Direct Run

# Process each input Fujitsu UPC BIOS image
for input_file in upc_exec :
	input_name,input_extension = os.path.splitext(os.path.basename(input_file))
	
	print('\n*** %s%s' % (input_name, input_extension))
	
	# Check if input file exists
	if not os.path.isfile(input_file) :
		print('\n    Error: This input file does not exist!')
		continue # Next input file
	
	with open(input_file, 'rb') as in_file : upc_data = in_file.read()
	
	if input_extension.upper() != '.UPC' or int.from_bytes(upc_data[0x0:0x4], 'little') + 0x8 != len(upc_data) :
		print('\n    Error: This is not a Fujitsu UPC BIOS image!')
		continue # Next input file
	
	output_file = input_file[:-4] + '.bin' # Decompressed filename
	
	# EFI/Tiano Decompression
	try :
		subprocess.run(['TianoCompress', '-d', input_file, '-o', output_file, '--uefi', '-q'], check = True, stdout = subprocess.DEVNULL)
		
		if os.path.getsize(output_file) != int.from_bytes(upc_data[0x4:0x8], 'little') : raise Exception('EFI_DECOMP_ERROR')
	except :
		print('\n    Error: Could not extract input file via TianoCompress!')
		input('           Make sure that "TianoCompress" executable exists!')
	
	print('\n    Extracted Fujitsu UPC BIOS image!')

input('\nDone!')

sys.exit(0)