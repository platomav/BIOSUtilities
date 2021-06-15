#!/usr/bin/env python3
#coding=utf-8

"""
Phoenix SCT Extract
Phoenix SCT BIOS Extractor
Copyright (C) 2021 Plato Mavropoulos
"""

title = 'Phoenix SCT BIOS Extractor v1.0'

print('\n' + title) # Print script title

import sys

# Detect Python version
sys_ver = sys.version_info
if sys_ver < (3,7) :
	sys.stdout.write('\n\nError: Python >= 3.7 required, not %d.%d!\n' % (sys_ver[0], sys_ver[1]))
	(raw_input if sys_ver[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
	sys.exit(1)

import os
import re
import lzma
import shutil
import ctypes
import argparse
import traceback

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
sct_parser = argparse.ArgumentParser()
sct_parser.add_argument('executables', type=argparse.FileType('r'), nargs='*')
sct_parser.add_argument('-p', '--path', help='parse files within given folder', type=str)
sct_params = sct_parser.parse_args()

# Get all files within path
def get_files(path) :
	inputs = []
	
	for root, _, files in os.walk(path):
		for name in files :
			inputs.append(os.path.join(root, name))
	
	return inputs

if len(sys.argv) >= 2 :
	if bool(sct_params.path) :
		sct_exec = get_files(sct_params.path) # CLI with --path
	else :
		sct_exec = []
		for executable in sct_params.executables :
			sct_exec.append(executable.name) # Drag & Drop
else :
	in_path = input('\nEnter the full folder path: ')
	sct_exec = get_files(in_path) # Direct Run

# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

class SCT_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Tag',					char*8),		# 0x00
		('Size',				uint32_t),		# 0x08
		('Count',				uint32_t),		# 0x0C
		# 0x10
	]
	
	def sct_print(self) :
		print('\n    Phoenix SCT Header:\n')
		print('        Tag   : %s' % self.Tag.decode('utf-8','replace').strip())
		print('        Size  : 0x%X' % self.Size)
		print('        Count : %d' % self.Count)

class SCT_MOD(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Name',				char*256),		# 0x000
		('Offset',				uint32_t),		# 0x100
		('Size',				uint32_t),		# 0x104
		('Compressed',			uint32_t),		# 0x108
		('Reserved',			uint32_t),		# 0x10C
		# 0x110
	]
	
	def sct_print(self) :	
		print('\n        Phoenix SCT Entry:\n')
		print('            Name       : %s' % self.Name.decode('utf-8','replace').strip())
		print('            Offset     : 0x%X' % self.Offset)
		print('            Size       : 0x%X' % self.Size)
		print('            Compressed : %s' % ['No','Yes'][self.Compressed])
		print('            Reserved   : 0x%X' % self.Reserved)

# Process ctypes Structure Classes
# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
def get_struct(buffer, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = buffer[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= len(buffer)) or (fit_len < struct_len) :
		print('\n    Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name.__name__))
		
		input('\n    Press enter to exit')
		
		sys.exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure

# Phoenix SCT BIOS Package Pattern ($PACK + Size + Count)
sct_pat = re.compile(br'\x24\x50\x41\x43\x4B\x00{3}..\x00{2}.\x00{3}', re.DOTALL)

# Get common ctypes Structure Sizes
sct_hdr_len = ctypes.sizeof(SCT_HDR)
sct_mod_len = ctypes.sizeof(SCT_MOD)

# Size of dummy/placeholder SCT Entries
sct_dummy_len = 0x200 # Top 2, Names only

# Process each input Phoenix SCT BIOS executable
for input_file in sct_exec :
	input_name,input_extension = os.path.splitext(os.path.basename(input_file))
	input_dir = os.path.dirname(os.path.abspath(input_file))
	
	print('\n*** %s%s' % (input_name, input_extension))
	
	# Check if input file exists
	if not os.path.isfile(input_file) :
		print('\n    Error: This input file does not exist!')
		continue # Next input file
	
	with open(input_file, 'rb') as in_file : input_data = in_file.read()
	
	sct_match = sct_pat.search(input_data) # Search for Phoenix SCT BIOS Pattern
	
	# Check if Phoenix SCT BIOS Pattern was found on executable
	if not sct_match :
		print('\n    Error: This is not a Phoenix SCT BIOS executable!')
		continue # Next input file
	
	output_path = os.path.join(input_dir, '%s%s' % (input_name, input_extension) + '_extracted') # Set extraction directory
	
	if os.path.isdir(output_path) : shutil.rmtree(output_path) # Delete any existing extraction directory
	
	os.mkdir(output_path) # Create extraction directory
	
	print('\n    Phoenix SecureCore Technology')
	
	sct_hdr = get_struct(input_data, sct_match.start(), SCT_HDR) # Parse SCT Header Structure
	sct_hdr.sct_print() # Print SCT Header Info
	
	# Check if reported SCT Header Size matches manual SCT Entry Count calculation
	if sct_hdr.Size != sct_hdr_len + sct_dummy_len + sct_hdr.Count * sct_mod_len :
		input('\n    Error: This Phoenix SCT BIOS image is corrupted!')
		continue # Next input file
	
	# Store all SCT $PACK Data w/o initial dummy/placeholder Entries
	pack_data = input_data[sct_match.end() + sct_dummy_len:sct_match.start() + sct_hdr.Size]
	
	# Parse each SCT Entry
	for e_idx in range(sct_hdr.Count) :
		mod_hdr = get_struct(pack_data, e_idx * sct_mod_len, SCT_MOD) # Parse SCT Entry Structure
		mod_hdr.sct_print() # Print SCT Entry Info
		
		mod_data = input_data[mod_hdr.Offset:mod_hdr.Offset + mod_hdr.Size] # Store SCT Entry Raw Data
		
		# Check if SCT Entry Raw Data is complete
		if len(mod_data) != mod_hdr.Size :
			input('\n        Error: This Phoenix SCT BIOS image is incomplete!')
		
		# Store SCT Entry LZMA Decompressed Data, when applicable
		if mod_hdr.Compressed : mod_data = lzma.LZMADecompressor().decompress(mod_data)
		
		# Replace common Windows reserved/illegal filename characters
		mod_fname = re.sub(r'[\\/*?:"<>|]', '_', mod_hdr.Name.decode('utf-8','replace').strip())
		
		with open(os.path.join(output_path, mod_fname), 'wb') as out : out.write(mod_data) # Store SCT Entry Data/File
	
	print('\n    Extracted Phoenix SCT BIOS executable!')

input('\nDone!')

sys.exit(0)