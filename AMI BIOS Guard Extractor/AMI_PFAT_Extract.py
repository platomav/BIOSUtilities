#!/usr/bin/env python3

"""
AMI PFAT Extract
AMI BIOS Guard Extractor
Copyright (C) 2018 Plato Mavropoulos
"""

print('AMI BIOS Guard Extractor v1.0')

import os
import sys
import ctypes
import struct

# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

# noinspection PyTypeChecker
class PFAT_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Size',			uint32_t),		# 0x00
		('Validation',		uint32_t),		# 0x04 Unknown 16-bit Checksum ?
		('Tag',				char*8),		# 0x04 _AMIPFAT
		('Control',			uint8_t),		# 0x10 0x4
		# 0x11
	]
	
	def pfat_print(self) :
		print('\nPFAT Main Header:\n')
		print('    Size       : 0x%X' % self.Size)
		print('    Validation : 0x%X' % self.Validation)
		print('    Tag        : %s' % self.Tag.decode('utf-8'))
		print('    Control    : 0x%X' % self.Control)

# noinspection PyTypeChecker
class PFAT_Block_Header(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Revision',		uint32_t),		# 0x00 PFAT
		('Platform',		char*16),		# 0x04
		('Unknown0',		uint32_t),		# 0x14
		('Unknown1',		uint32_t),		# 0x18
		('FlagsSize',		uint32_t),		# 0x1C From Block Header end
		('DataSize',		uint32_t),		# 0x20 From Block Flags end
		('Unknown2',		uint32_t),		# 0x24
		('Unknown3',		uint32_t),		# 0x28
		('Unknown4',		uint32_t),		# 0x2C
		# 0x30
	]
	
	def __init__(self, count, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.count = count
	
	def pfat_print(self) :
		print('\n    PFAT Block %s Header:\n' % self.count)
		print('        Revision   : %d' % self.Revision)
		print('        Platform   : %s' % self.Platform.decode('utf-8'))
		print('        Unknown 0  : 0x%X' % self.Unknown0)
		print('        Unknown 1  : 0x%X' % self.Unknown1)
		print('        Flags Size : 0x%X' % self.FlagsSize)
		print('        Data Size  : 0x%X' % self.DataSize)
		print('        Unknown 2  : 0x%X' % self.Unknown2)
		print('        Unknown 3  : 0x%X' % self.Unknown3)
		print('        Unknown 4  : 0x%X' % self.Unknown4)
		
# noinspection PyTypeChecker
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
		RSAPublicKey = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.PublicKey))
		RSASignature = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Signature))
		
		print('\n    PFAT Block %s Signature:\n' % self.count)
		print('        Unknown 0  : 0x%X' % self.Unknown0)
		print('        Unknown 1  : 0x%X' % self.Unknown1)
		print('        Public Key : %s [...]' % RSAPublicKey[:8])
		print('        Exponent   : 0x%X' % self.Exponent)
		print('        Signature  : %s [...]' % RSASignature[:8])

# Process ctypes Structure Classes
def get_struct(buffer, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = buffer[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= len(buffer)) or (fit_len < struct_len) :
		print('Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name))
		sys.exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure
	
if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	pfat = sys.argv[1:]
else :
	# Folder path
	pfat = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			pfat.append(os.path.join(root, name))

for input_file in pfat :
	with open(input_file, 'rb') as in_file : buffer = in_file.read()
	final_image = b''
	block_name = ''
	block_count = 0
	blocks = []
	
	pfat_hdr = get_struct(buffer, 0, PFAT_Header)
	
	if pfat_hdr.Tag.decode('utf-8', 'ignore') != '_AMIPFAT' : continue
	
	hdr_size = pfat_hdr.Size
	hdr_data = buffer[0x11:hdr_size].decode('utf-8').splitlines()
	
	pfat_hdr.pfat_print()
	print('    Title      : %s' % hdr_data[0])
	
	for entry in hdr_data[1:] :
		entry_data = entry.split(' ')
		entry_data = [s for s in entry_data if s != '']
		entry_flash = int(entry_data[0])
		entry_param = entry_data[1]
		entry_blocks = int(entry_data[2])
		entry_name = entry_data[3][1:]
		
		for i in range(entry_blocks) : blocks.append([entry_name, entry_param, entry_flash, i + 1, entry_blocks])
		
		block_count += entry_blocks
	
	block_start = hdr_size
	for i in range(block_count) :
		if blocks[i][0] != block_name : print('\n%s (Parameter: %s, Update: %s)' % (blocks[i][0], blocks[i][1], ['No','Yes'][blocks[i][2]]))
		block_hdr = get_struct(buffer, block_start, PFAT_Block_Header, ['%d/%d' % (blocks[i][3], blocks[i][4])])
		block_hdr_size = ctypes.sizeof(PFAT_Block_Header)
		block_flag_size = block_hdr.FlagsSize
		flag_data = buffer[block_start + block_hdr_size:block_start + block_hdr_size + block_flag_size] # Flags not parsed
		block_data_start = block_start + block_hdr_size + block_flag_size
		block_data_end = block_data_start + block_hdr.DataSize
		block_hdr.pfat_print()
		
		block_rsa = get_struct(buffer, block_data_end, PFAT_Block_RSA, ['%d/%d' % (blocks[i][3], blocks[i][4])])
		block_rsa_size = ctypes.sizeof(PFAT_Block_RSA)
		#block_rsa_exp = block_rsa.Exponent
		#block_rsa_pkey = int((''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(block_rsa.PublicKey))), 16)
		#block_rsa_sign = int((''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(block_rsa.Signature))), 16)
		#block_rsa_sign_dec = '%X' % pow(block_rsa_sign, block_rsa_exp, block_rsa_pkey) # Decrypted signature is 4096 bits
		block_rsa.pfat_print()
		
		final_image += buffer[block_data_start:block_data_end]
		
		block_name = blocks[i][0]
		block_start = block_data_end + block_rsa_size
		
	with open('%s_unpacked.bin' % os.path.basename(input_file), 'wb') as final : final.write(final_image)
		
else :
	input('\nDone!')