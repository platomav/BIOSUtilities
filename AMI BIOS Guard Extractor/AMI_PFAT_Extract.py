#!/usr/bin/env python3
#coding=utf-8

"""
AMI PFAT Extract
AMI BIOS Guard Extractor
Copyright (C) 2018-2021 Plato Mavropoulos
"""

print('AMI BIOS Guard Extractor v3.2')

import sys

# Detect Python version
sys_ver = sys.version_info
if sys_ver < (3,7) :
	sys.stdout.write('\n\nError: Python >= 3.7 required, not %d.%d!\n' % (sys_ver[0], sys_ver[1]))
	(raw_input if sys_ver[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
	sys.exit(1)

import os
import re
import ctypes
import shutil
import traceback

# https://stackoverflow.com/a/781074 by Torsten Marek
def show_exception_and_exit(exc_type, exc_value, tb) :
	if exc_type is KeyboardInterrupt :
		print('\n')
	else :
		print('\nError: ABGE crashed, please report the following:\n')
		traceback.print_exception(exc_type, exc_value, tb)
	input('\nPress enter to exit')
	sys.exit(1)

# Pause after any unexpected python exception
sys.excepthook = show_exception_and_exit

sys.dont_write_bytecode = True

# https://github.com/allowitsme/big-tool by Dmitry Frolov
try :
	from big_script_tool import BigScript
	is_bgst = True
except :
	is_bgst = False

# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

class PFAT_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Size',			uint32_t),		# 0x00
		('Checksum',		uint32_t),		# 0x04 Unknown 16-bits
		('Tag',				char*8),		# 0x04 _AMIPFAT
		('Flags',			uint8_t),		# 0x10
		# 0x11
	]
	
	def pfat_print(self) :
		print('\n    PFAT Main Header:\n')
		print('        Size        : 0x%X' % self.Size)
		print('        Checksum    : 0x%0.4X' % self.Checksum)
		print('        Tag         : %s' % self.Tag.decode('utf-8'))
		print('        Flags       : 0x%0.2X' % self.Flags)

class PFAT_Block_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('PFATVerMajor',	uint16_t),		# 0x00
		('PFATVerMinor',	uint16_t),		# 0x02
		('PlatformID',		uint8_t*16),	# 0x04
		('Attributes',		uint32_t),		# 0x14
		('ScriptVerMajor',	uint16_t),		# 0x16
		('ScriptVerMinor',	uint16_t),		# 0x18
		('ScriptSize',		uint32_t),		# 0x1C
		('DataSize',		uint32_t),		# 0x20
		('BIOSSVN',			uint32_t),		# 0x24
		('ECSVN',			uint32_t),		# 0x28
		('VendorInfo',		uint32_t),		# 0x2C
		# 0x30
	]
	
	def __init__(self, count, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.count = count
	
	def get_flags(self) :
		attr = PFAT_Block_Header_GetAttributes()
		attr.asbytes = self.Attributes
		
		return attr.b.SFAM, attr.b.ProtectEC, attr.b.GFXMitDis, attr.b.FTU, attr.b.Reserved
	
	def pfat_print(self) :
		no_yes = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		PlatformID = bytes(self.PlatformID).strip(b'\x00')
		if PlatformID.isalpha() : # STRING
			PlatformID = PlatformID.decode('utf-8', 'ignore')
		else : # GUID
			PlatformID = '%0.*X' % (0x10 * 2, int.from_bytes(self.PlatformID, 'big'))
			PlatformID = '{%s-%s-%s-%s-%s}' % (PlatformID[:8], PlatformID[8:12], PlatformID[12:16], PlatformID[16:20], PlatformID[20:])
		
		print('\n            PFAT Block %s Header:\n' % self.count)
		print('                PFAT Version              : %d.%d' % (self.PFATVerMajor, self.PFATVerMinor))
		print('                Platform ID               : %s' % PlatformID)
		print('                Signed Flash Address Map  : %s' % no_yes[f1])
		print('                Protected EC OpCodes      : %s' % no_yes[f2])
		print('                Graphics Security Disable : %s' % no_yes[f3])
		print('                Fault Tolerant Update     : %s' % no_yes[f4])
		print('                Attributes Reserved       : 0x%X' % f5)
		print('                Script Version            : %d.%d' % (self.ScriptVerMajor, self.ScriptVerMinor))
		print('                Script Size               : 0x%X' % self.ScriptSize)
		print('                Data Size                 : 0x%X' % self.DataSize)
		print('                BIOS SVN                  : 0x%X' % self.BIOSSVN)
		print('                EC SVN                    : 0x%X' % self.ECSVN)
		print('                Vendor Info               : 0x%X' % self.VendorInfo)
		
class PFAT_Block_Header_Attributes(ctypes.LittleEndianStructure):
	_fields_ = [
		('SFAM', uint32_t, 1), # Signed Flash Address Map
		('ProtectEC', uint32_t, 1), # Protected EC OpCodes
		('GFXMitDis', uint32_t, 1), # GFX Security Disable
		('FTU', uint32_t, 1), # Fault Tolerant Update
		('Reserved', uint32_t, 28)
	]

class PFAT_Block_Header_GetAttributes(ctypes.Union):
	_fields_ = [
		('b', PFAT_Block_Header_Attributes),
		('asbytes', uint32_t)
	]

class PFAT_Block_RSA(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Unknown0',		uint32_t),		# 0x00
		('Unknown1',		uint32_t),		# 0x04
		('PublicKey',		uint32_t*64),	# 0x08
		('Exponent',		uint32_t),		# 0x108
		('Signature',		uint32_t*64),	# 0x10C
		# 0x20C
	]
	
	def __init__(self, count, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.count = count
	
	def pfat_print(self) :
		PublicKey = '%0.*X' % (0x100 * 2, int.from_bytes(self.PublicKey, 'little'))
		Signature = '%0.*X' % (0x100 * 2, int.from_bytes(self.Signature, 'little'))
		
		print('\n            PFAT Block %s Signature:\n' % self.count)
		print('                Unknown 0                 : 0x%X' % self.Unknown0)
		print('                Unknown 1                 : 0x%X' % self.Unknown1)
		print('                Public Key                : %s [...]' % PublicKey[:8])
		print('                Exponent                  : 0x%X' % self.Exponent)
		print('                Signature                 : %s [...]' % Signature[:8])

# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
def get_struct(buffer, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = buffer[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= len(buffer)) or (fit_len < struct_len) :
		input('\n    Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name.__name__))
		sys.exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure
	
if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	ami_pfat = sys.argv[1:]
else :
	# Folder path
	ami_pfat = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, _, files in os.walk(in_path):
		for name in files :
			ami_pfat.append(os.path.join(root, name))

pfat_index = 1
input_name = ''
input_extension = ''
output_path = ''
block_hdr_size = ctypes.sizeof(PFAT_Block_Header)
block_rsa_size = ctypes.sizeof(PFAT_Block_RSA)
pfat_pat = re.compile(b'_AMIPFAT.AMI_BIOS_GUARD_FLASH_CONFIGURATIONS', re.DOTALL)

for input_file in ami_pfat :
	file_data = b''
	final_data = b''
	block_name = ''
	block_count = 0
	file_index = 0
	blocks = []
	
	with open(input_file, 'rb') as in_file : buffer = in_file.read()
	
	pfat_match = pfat_pat.search(buffer)
	
	if pfat_index == 1 :
		input_name,input_extension = os.path.splitext(os.path.basename(input_file))
		input_dir = os.path.dirname(os.path.abspath(input_file))
		
		print('\n*** %s%s' % (input_name, input_extension))
		
		if not pfat_match :
			print('\n        Error: This is not an AMI BIOS Guard (PFAT) image!')
			continue
		
		output_path = os.path.join(input_dir, '%s%s' % (input_name, input_extension) + '_extracted') # Set extraction directory
		
		if os.path.isdir(output_path) : shutil.rmtree(output_path) # Delete any existing extraction directory
		
		os.mkdir(output_path) # Create extraction directory
	
	if not pfat_match : continue
	
	buffer = buffer[pfat_match.start() - 0x8:]
	
	pfat_hdr = get_struct(buffer, 0, PFAT_Header)
	
	hdr_size = pfat_hdr.Size
	hdr_data = buffer[0x11:hdr_size].decode('utf-8').splitlines()
	
	pfat_hdr.pfat_print()
	print('        Title       : %s' % hdr_data[0])
		
	file_path = os.path.join(output_path, '%s%s -- %d' % (input_name, input_extension, pfat_index))
	
	for entry in hdr_data[1:] :
		entry_data = entry.split(' ')
		entry_data = [s for s in entry_data if s != '']
		entry_flags = int(entry_data[0])
		entry_param = entry_data[1]
		entry_blocks = int(entry_data[2])
		entry_name = entry_data[3][1:]
		
		for i in range(entry_blocks) : blocks.append([entry_name, entry_param, entry_flags, i + 1, entry_blocks])
		
		block_count += entry_blocks
	
	block_start = hdr_size
	for i in range(block_count) :
		is_file_start = blocks[i][0] != block_name
		
		if is_file_start : print('\n        %s (Parameter: %s, Flags: 0x%X)' % (blocks[i][0], blocks[i][1], blocks[i][2]))
			
		block_hdr = get_struct(buffer, block_start, PFAT_Block_Header, ['%d/%d' % (blocks[i][3], blocks[i][4])])
		block_hdr.pfat_print()
		
		block_script_size = block_hdr.ScriptSize
		block_script_data = buffer[block_start + block_hdr_size:block_start + block_hdr_size + block_script_size]
		block_data_start = block_start + block_hdr_size + block_script_size
		block_data_end = block_data_start + block_hdr.DataSize
		block_data = buffer[block_data_start:block_data_end]
		
		block_rsa = get_struct(buffer, block_data_end, PFAT_Block_RSA, ['%d/%d' % (blocks[i][3], blocks[i][4])])
		block_rsa.pfat_print()
		
		print('\n            PFAT Block %d/%d Script:\n' % (blocks[i][3], blocks[i][4]))
		is_opcode_div = len(block_script_data) % 8 == 0
		is_begin_end = block_script_data[:8] + block_script_data[-8:] == b'\x01' + b'\x00' * 7 + b'\xFF' + b'\x00' * 7
		if is_opcode_div and is_begin_end and is_bgst :
			block_script_decomp = BigScript(code_bytes=block_script_data)
			block_script_lines = block_script_decomp.to_string().replace('\t','    ').split('\n')
			for line in block_script_lines :
				spacing = ' ' * 16 if line.endswith(('begin','end',':')) else ' ' * 24
				operands = [op for op in line.split(' ') if op != '']
				print(spacing + ('{:<12s}' + '{:<11s}' * (len(operands) - 1)).format(*operands))
		elif not is_opcode_div :
			print('                Error: Script not divisible by OpCode length!')
		elif not is_begin_end :
			print('                Error: Script lacks Begin and/or End OpCodes!')
		elif not is_bgst :
			print('                Error: BIOS Guard Script Tool dependency missing!')
		
		file_data += block_data
		final_data += block_data
		
		if i and is_file_start and file_data :
			file_index += 1
			with open('%s_%0.2d -- %s' % (file_path, file_index, block_name), 'wb') as o : o.write(file_data)
			file_data = b''
		
		block_name = blocks[i][0]
		block_start = block_data_end + block_rsa_size
	
	with open('%s_%0.2d -- %s' % (file_path, file_index + 1, block_name), 'wb') as o : o.write(file_data) # Last File
	
	eof_data = buffer[block_start:] # Store any data after the end of PFAT
	
	with open('%s_00 -- AMI_PFAT_%d_DATA_ALL.bin' % (file_path, pfat_index), 'wb') as final : final.write(final_data + eof_data)
	
	if eof_data[:-0x100] != b'\xFF' * (len(eof_data) - 0x100) :
		eof_path = '%s_%0.2d -- AMI_PFAT_%d_DATA_END.bin' % (file_path, file_index + 2, pfat_index)
		with open(eof_path, 'wb') as final : final.write(eof_data)
		
		if pfat_pat.search(eof_data) :
			pfat_index += 1
			ami_pfat_index = ami_pfat.index(input_file) + 1
			ami_pfat.insert(ami_pfat_index, eof_path)
		else :
			pfat_index = 1
		
input('\nDone!')