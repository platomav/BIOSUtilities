#!/usr/bin/env python3
#coding=utf-8

"""
Dell PFS Extract
Dell PFS Update Extractor
Copyright (C) 2018-2021 Plato Mavropoulos
"""

title = 'Dell PFS Update Extractor v5.0'

import sys

# Detect Python version
sys_py = sys.version_info

# Check Python version
if sys_py < (3,7) :
	sys.stdout.write('%s\n\nError: Python >= 3.7 required, not %d.%d!\n' % (title, sys_py[0], sys_py[1]))
	
	if '--auto-exit' not in sys.argv and '-e' not in sys.argv :
		(raw_input if sys_py[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
	
	sys.exit(1)

# Detect OS platform
sys_os = sys.platform

# Check OS platform
if sys_os == 'win32' :
	sys.stdout.reconfigure(encoding='utf-8') # Fix Windows Unicode console redirection
elif sys_os.startswith('linux') or sys_os == 'darwin' or sys_os.find('bsd') != -1 :
	pass # Supported/Tested
else :
	print('%s\n\nError: Unsupported platform "%s"!\n' % (title, sys_os))
	
	if '--auto-exit' not in sys.argv and '-e' not in sys.argv : input('Press enter to exit')
	
	sys.exit(1)

# Skip __pycache__ generation
sys.dont_write_bytecode = True

# Python imports
import os
import re
import zlib
import lzma
import shutil
import ctypes
import inspect
import pathlib
import argparse
import traceback

# Optional imports
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

# Dell PFS Header Structure
class PFS_DELL_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Tag',					char*8),		# 0x00
		('HeaderVersion',		uint32_t),		# 0x08
		('PayloadSize',			uint32_t),		# 0x0C
		# 0x10
	]
	
	def pfs_print(self, padd) :
		print('\n%sPFS Header:\n' % (' ' * (padd - 4)))
		print('%sHeader Tag     : %s' % (' ' * padd, self.Tag.decode('utf-8')))
		print('%sHeader Version : %d' % (' ' * padd, self.HeaderVersion))
		print('%sPayload Size   : 0x%X' % (' ' * padd, self.PayloadSize))

# Dell PFS Footer Structure	
class PFS_DELL_FTR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('PayloadSize',			uint32_t),		# 0x00
		('Checksum',			uint32_t),		# 0x04 ~CRC32 w/ Vector 0
		('Tag',					char*8),		# 0x08
		# 0x10
	]
	
	def pfs_print(self, padd) :
		print('\n%sPFS Footer:\n' % (' ' * (padd - 4)))
		print('%sPayload Size     : 0x%X' % (' ' * padd, self.PayloadSize))
		print('%sPayload Checksum : 0x%0.8X' % (' ' * padd, self.Checksum))
		print('%sFooter Tag       : %s' % (' ' * padd, self.Tag.decode('utf-8')))

# Dell PFS Entry Revision 1 Structure
class PFS_ENTRY_R1(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('GUID',				uint32_t*4),	# 0x00 Little Endian
		('HeaderVersion',		uint32_t),		# 0x10 1
		('VersionType',			uint8_t*4),		# 0x14
		('Version',				uint16_t*4),	# 0x18
		('Reserved',			uint64_t),		# 0x20
		('DataSize',			uint32_t),		# 0x28
		('DataSigSize',			uint32_t),		# 0x2C
		('DataMetSize',			uint32_t),		# 0x30
		('DataMetSigSize',		uint32_t),		# 0x34
		('Unknown',				uint32_t*4),	# 0x38
		# 0x48
	]
	
	def pfs_print(self, padd) :
		GUID = '%0.*X' % (0x10 * 2, int.from_bytes(self.GUID, 'little'))
		Unknown = '%0.*X' % (0x10 * 2, int.from_bytes(self.Unknown, 'little'))
		Version = get_entry_ver(self.Version, self.VersionType, padd - 4)
		
		print('\n%sPFS Entry:\n' % (' ' * (padd - 4)))
		print('%sEntry GUID              : %s' % (' ' * padd, GUID))
		print('%sEntry Version           : %d' % (' ' * padd, self.HeaderVersion))
		print('%sPayload Version         : %s' % (' ' * padd, Version))
		print('%sReserved                : 0x%X' % (' ' * padd, self.Reserved))
		print('%sPayload Data Size       : 0x%X' % (' ' * padd, self.DataSize))
		print('%sPayload Signature Size  : 0x%X' % (' ' * padd, self.DataSigSize))
		print('%sMetadata Data Size      : 0x%X' % (' ' * padd, self.DataMetSize))
		print('%sMetadata Signature Size : 0x%X' % (' ' * padd, self.DataMetSigSize))
		print('%sUnknown                 : %s' % (' ' * padd, Unknown))

# Dell PFS Entry Revision 2 Structure
class PFS_ENTRY_R2(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('GUID',				uint32_t*4),	# 0x00 Little Endian
		('HeaderVersion',		uint32_t),		# 0x10 2
		('VersionType',			uint8_t*4),		# 0x14
		('Version',				uint16_t*4),	# 0x18
		('Reserved',			uint64_t),		# 0x20
		('DataSize',			uint32_t),		# 0x28
		('DataSigSize',			uint32_t),		# 0x2C
		('DataMetSize',			uint32_t),		# 0x30
		('DataMetSigSize',		uint32_t),		# 0x34
		('Unknown',				uint32_t*8),	# 0x38
		# 0x58
	]
	
	def pfs_print(self, padd) :
		GUID = '%0.*X' % (0x10 * 2, int.from_bytes(self.GUID, 'little'))
		Unknown = '%0.*X' % (0x20 * 2, int.from_bytes(self.Unknown, 'little'))
		Version = get_entry_ver(self.Version, self.VersionType, padd - 4)
		
		print('\n%sPFS Entry:\n' % (' ' * (padd - 4)))
		print('%sEntry GUID              : %s' % (' ' * padd, GUID))
		print('%sEntry Version           : %d' % (' ' * padd, self.HeaderVersion))
		print('%sPayload Version         : %s' % (' ' * padd, Version))
		print('%sReserved                : 0x%X' % (' ' * padd, self.Reserved))
		print('%sPayload Data Size       : 0x%X' % (' ' * padd, self.DataSize))
		print('%sPayload Signature Size  : 0x%X' % (' ' * padd, self.DataSigSize))
		print('%sMetadata Data Size      : 0x%X' % (' ' * padd, self.DataMetSize))
		print('%sMetadata Signature Size : 0x%X' % (' ' * padd, self.DataMetSigSize))
		print('%sUnknown                 : %s' % (' ' * padd, Unknown))

# Dell PFS Information Header Structure
class PFS_INFO_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('HeaderVersion',		uint32_t),		# 0x00
		('GUID',				uint32_t*4),	# 0x04 Little Endian
		# 0x14
	]
	
	def pfs_print(self, padd) :
		GUID = '%0.*X' % (0x10 * 2, int.from_bytes(self.GUID, 'little'))
		
		print('\n%sPFS Information Header:\n' % (' ' * (padd - 4)))
		print('%sInfo Version : %d' % (' ' * padd, self.HeaderVersion))
		print('%sEntry GUID   : %s' % (' ' * padd, GUID))

# Dell PFS FileName Header Structure
class PFS_NAME_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Version',				uint16_t*4),	# 0x00
		('VersionType',			uint8_t*4),		# 0x08
		('CharacterCount',		uint16_t),		# 0x0C UTF-16 2-byte Characters
		# 0x0E
	]
	
	def pfs_print(self, padd) :
		Version = get_entry_ver(self.Version, self.VersionType, padd - 4)
		
		print('\n%sPFS FileName Entry:\n' % (' ' * (padd - 4)))
		print('%sPayload Version : %s' % (' ' * padd, Version))
		print('%sCharacter Count : %d' % (' ' * padd, self.CharacterCount))

# Dell PFS Metadata Header Structure
class PFS_META_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('ModelIDs',			char*501),		# 0x000
		('FileName',			char*100),		# 0x1F5
		('FileVersion',			char*33),		# 0x259
		('Date',				char*33),		# 0x27A
		('Brand',				char*80),		# 0x29B
		('ModelFile',			char*80),		# 0x2EB
		('ModelName',			char*100),		# 0x33B
		('ModelVersion',		char*33),		# 0x39F
		# 0x3C0
	]
	
	def pfs_print(self, padd) :
		print('\n%sPFS Metadata Information:\n' % (' ' * (padd - 4)))
		print('%sModel IDs     : %s' % (' ' * padd, self.ModelIDs.decode('utf-8').strip(',END')))
		print('%sFile Name     : %s' % (' ' * padd, self.FileName.decode('utf-8')))
		print('%sFile Version  : %s' % (' ' * padd, self.FileVersion.decode('utf-8')))
		print('%sDate          : %s' % (' ' * padd, self.Date.decode('utf-8')))
		print('%sBrand         : %s' % (' ' * padd, self.Brand.decode('utf-8')))
		print('%sModel File    : %s' % (' ' * padd, self.ModelFile.decode('utf-8')))
		print('%sModel Name    : %s' % (' ' * padd, self.ModelName.decode('utf-8')))
		print('%sModel Version : %s' % (' ' * padd, self.ModelVersion.decode('utf-8')))
		
	def pfs_write(self) :
		return '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' % (self.ModelIDs.decode('utf-8').strip(',END'), self.FileName.decode('utf-8'),
				self.FileVersion.decode('utf-8'), self.Date.decode('utf-8'), self.Brand.decode('utf-8'), self.ModelFile.decode('utf-8'),
				self.ModelName.decode('utf-8'), self.ModelVersion.decode('utf-8'))

# Dell PFS BIOS Guard Header Structure
class PFS_PFAT_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('PFATVerMajor',		uint16_t),		# 0x00
		('PFATVerMinor',		uint16_t),		# 0x02
		('PlatformID',			uint8_t*16),	# 0x04
		('Attributes',			uint32_t),		# 0x14
		('ScriptVerMajor',		uint16_t),		# 0x16
		('ScriptVerMinor',		uint16_t),		# 0x18
		('ScriptSize',			uint32_t),		# 0x1C
		('DataSize',			uint32_t),		# 0x20
		('BIOSSVN',				uint32_t),		# 0x24
		('ECSVN',				uint32_t),		# 0x28
		('VendorInfo',			uint32_t),		# 0x2C
		# 0x30
	]
	
	def __init__(self, count, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.count = count
	
	def get_flags(self) :
		attr = PFS_PFAT_HDR_ATTRIBUTES_GET()
		attr.asbytes = self.Attributes
		
		return attr.b.SFAM, attr.b.ProtectEC, attr.b.GFXMitDis, attr.b.FTU, attr.b.Reserved
	
	def pfs_print(self, padd) :
		no_yes = ['No','Yes']
		f1,f2,f3,f4,f5 = self.get_flags()
		
		PlatformID = bytes(self.PlatformID).strip(b'\x00')
		try : # STRING
			PlatformID = PlatformID.decode('utf-8') 
		except : # GUID
			PlatformID = '%0.*X' % (0x10 * 2, int.from_bytes(self.PlatformID, 'big'))
			PlatformID = '{%s-%s-%s-%s-%s}' % (PlatformID[:8], PlatformID[8:12], PlatformID[12:16], PlatformID[16:20], PlatformID[20:])
		
		print('\n%sPFAT Block %d Header:\n' % (' ' * (padd - 4), self.count))
		print('%sPFAT Version              : %d.%d' % (' ' * padd, self.PFATVerMajor, self.PFATVerMinor))
		print('%sPlatform ID               : %s' % (' ' * padd, PlatformID))
		print('%sSigned Flash Address Map  : %s' % (' ' * padd, no_yes[f1]))
		print('%sProtected EC OpCodes      : %s' % (' ' * padd, no_yes[f2]))
		print('%sGraphics Security Disable : %s' % (' ' * padd, no_yes[f3]))
		print('%sFault Tolerant Update     : %s' % (' ' * padd, no_yes[f4]))
		print('%sAttributes Reserved       : 0x%X' % (' ' * padd, f5))
		print('%sScript Version            : %d.%d' % (' ' * padd, self.ScriptVerMajor, self.ScriptVerMinor))
		print('%sScript Size               : 0x%X' % (' ' * padd, self.ScriptSize))
		print('%sData Size                 : 0x%X' % (' ' * padd, self.DataSize))
		print('%sBIOS SVN                  : 0x%X' % (' ' * padd, self.BIOSSVN))
		print('%sEC SVN                    : 0x%X' % (' ' * padd, self.ECSVN))
		print('%sVendor Info               : 0x%X' % (' ' * padd, self.VendorInfo))

# Dell PFS BIOS Guard Attributes Flags Structure
class PFS_PFAT_HDR_ATTRIBUTES(ctypes.LittleEndianStructure):
	_fields_ = [
		('SFAM', uint32_t, 1), # Signed Flash Address Map
		('ProtectEC', uint32_t, 1), # Protected EC OpCodes
		('GFXMitDis', uint32_t, 1), # GFX Security Disable
		('FTU', uint32_t, 1), # Fault Tolerant Update
		('Reserved', uint32_t, 28)
	]

# Dell PFS BIOS Guard Attributes Get Structure
class PFS_PFAT_HDR_ATTRIBUTES_GET(ctypes.Union):
	_fields_ = [
		('b', PFS_PFAT_HDR_ATTRIBUTES),
		('asbytes', uint32_t)
	]

# Dell PFS BIOS Guard Signature Structure
class PFS_PFAT_SIG(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Unknown0',			uint32_t),		# 0x00
		('Unknown1',			uint32_t),		# 0x04
		('PublicKey',			uint32_t*64),	# 0x08
		('Exponent',			uint32_t),		# 0x108
		('Signature',			uint32_t*64),	# 0x10C
		# 0x20C
	]
	
	def __init__(self, count, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.count = count
	
	def pfs_print(self, padd) :
		PublicKey = '%0.*X' % (0x100 * 2, int.from_bytes(self.PublicKey, 'little'))
		Signature = '%0.*X' % (0x100 * 2, int.from_bytes(self.Signature, 'little'))
		
		print('\n%sPFAT Block %d Signature:\n' % (' ' * (padd - 4), self.count))
		print('%sUnknown 0  : 0x%X' % (' ' * padd, self.Unknown0))
		print('%sUnknown 1  : 0x%X' % (' ' * padd, self.Unknown1))
		print('%sPublic Key : %s [...]' % (' ' * padd, PublicKey[:32]))
		print('%sExponent   : 0x%X' % (' ' * padd, self.Exponent))
		print('%sSignature  : %s [...]' % (' ' * padd, Signature[:32]))

# Dell PFS BIOS Guard Metadata Structure
class PFS_PFAT_MET(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('OffsetTop',			uint32_t),		# 0x00
		('Unknown0',			uint32_t),		# 0x04
		('OffsetBase',			uint32_t),		# 0x08
		('BlockSize',			uint32_t),		# 0x0C
		('Unknown1',			uint32_t),		# 0x10
		('Unknown2',			uint32_t),		# 0x14
		('Unknown3',			uint8_t),		# 0x18
		# 0x19
	]
	
	def __init__(self, count, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.count = count
	
	def pfs_print(self, padd) :
		print('\n%sPFAT Block %d Metadata:\n' % (' ' * (padd - 4), self.count))
		print('%sOffset Top  : 0x%X' % (' ' * padd, self.OffsetTop))
		print('%sUnknown 0   : 0x%X' % (' ' * padd, self.Unknown0))
		print('%sOffset Base : 0x%X' % (' ' * padd, self.OffsetBase))
		print('%sBlock Size  : 0x%X' % (' ' * padd, self.BlockSize))
		print('%sUnknown 1   : 0x%X' % (' ' * padd, self.Unknown1))
		print('%sUnknown 2   : 0x%X' % (' ' * padd, self.Unknown2))
		print('%sUnknown 3   : 0x%X' % (' ' * padd, self.Unknown3))

# Dell PFS Update Analysis
def main(exit_code, pfs_input_images) :
	# Process each input Dell PFS update image
	for input_file in pfs_input_images :
		input_name,input_ext = os.path.splitext(os.path.basename(input_file))
		input_dir = os.path.dirname(os.path.abspath(input_file))
		
		print('\n*** %s%s' % (input_name, input_ext))
		
		# Check if input file exists
		if not os.path.isfile(input_file) :
			print('\n    Error: This input file does not exist!')
			continue # Next input file
		
		with open(input_file, 'rb') as in_file : input_data = in_file.read()
		
		# Search input image for ThinOS PKG 7zXZ section header
		lzma_pkg_hdr_match = lzma_pkg_header.search(input_data)
		
		# Decompress ThinOS PKG 7zXZ section first, if present
		if lzma_pkg_hdr_match :
			lzma_len_off = lzma_pkg_hdr_match.start() + 0x10
			lzma_len_int = int.from_bytes(input_data[lzma_len_off:lzma_len_off + 0x4], 'little')
			lzma_bin_off = lzma_pkg_hdr_match.end() - 0x5
			lzma_bin_dat = input_data[lzma_bin_off:lzma_bin_off + lzma_len_int]
			
			# Check if the compressed 7zXZ stream is complete, based on header
			if len(lzma_bin_dat) != lzma_len_int :
				print('\n    Error: This Dell ThinOS PKG update image is corrupted!')
				continue # Next input file
			
			input_data = lzma.decompress(lzma_bin_dat)
		
		# Search input image for PFS ZLIB Sections
		pfs_zlib_offsets = get_section_offsets(input_data)
		
		if not pfs_zlib_offsets :
			print('\n    Error: This is not a Dell PFS update image!')
			continue # Next input file
		
		# Set user extraction path
		extract_path_user = get_absolute_path(args.output_dir)
		
		# Set main extraction path (optional user specified path taken into account)
		extract_path_main = os.path.join(extract_path_user, '%s%s' % (input_name, input_ext) + '_extracted')
		
		# Parse each PFS ZLIB Section
		for offset in pfs_zlib_offsets :
			# Call the PFS ZLIB Section Parser function
			pfs_section_parse(input_data, offset, extract_path_main, ' ' + input_name, 1, 1, False, 4)
		
		exit_code -= 1 # Adjust exit code to reflect extraction progress
	
	if not bool(args.auto_exit) : input('\nDone!')
	
	return exit_code

# Get PFS ZLIB Section Offsets
def get_section_offsets(buffer) :
	pfs_zlib_init = list(pfs_zlib_header.finditer(buffer))
	
	if not pfs_zlib_init : return [] # No PFS ZLIB detected
	
	pfs_zlib_list = [] # Initialize PFS ZLIB offset list
	
	# Remove duplicate/nested PFS ZLIB offsets
	for zlib_c in pfs_zlib_init :
		is_duplicate = False # Initialize duplicate/nested PFS ZLIB offset
		
		for zlib_o in pfs_zlib_init :
			zlib_o_size = int.from_bytes(buffer[zlib_o.start() - 0x5:zlib_o.start() - 0x1], 'little')
			
			# If current PFS ZLIB offset is within another PFS ZLIB range (start-end), set as duplicate
			if zlib_o.start() < zlib_c.start() < zlib_o.start() + zlib_o_size : is_duplicate = True
		
		if not is_duplicate : pfs_zlib_list.append(zlib_c.start())
	
	return pfs_zlib_list

# Dell PFS ZLIB Section Parser
def pfs_section_parse(zlib_data, zlib_start, output_path, pfs_name, pfs_index, pfs_count, is_rec, padd) :
	is_zlib_error = False # Initialize PFS ZLIB-related error state
	
	section_type = zlib_data[zlib_start - 0x1] # Byte before PFS ZLIB Section pattern is Section Type (e.g. AA, BB)
	section_name = section_dict[section_type] if section_type in section_dict else 'Unknown (%0.2X)' % section_type
	
	# Set PFS ZLIB Section extraction sub-directory path
	section_path = os.path.join(output_path, section_name)
	
	# Delete existing extraction sub-directory (not in recursions)
	if os.path.isdir(section_path) and not is_rec : shutil.rmtree(section_path)
	
	# Create extraction sub-directory
	if not os.path.isdir(section_path) : os.makedirs(section_path)
	
	# Store the compressed zlib stream start offset
	compressed_start = zlib_start + 0xB
	
	# Store the PFS ZLIB section header start offset
	header_start = zlib_start - 0x5
	
	# Store the PFS ZLIB section header contents (16 bytes)
	header_data = zlib_data[header_start:compressed_start]
	
	# Check if the PFS ZLIB section header Checksum XOR 8 is valid
	if chk_xor_8(header_data[:0xF], 0) != header_data[0xF] :
		print('\n%sError: Invalid Dell PFS ZLIB section Header Checksum!' % (' ' * padd))
		is_zlib_error = True
	
	# Store the compressed zlib stream size from the header contents
	compressed_size_hdr = int.from_bytes(header_data[:0x4], 'little')
	
	# Store the compressed zlib stream end offset
	compressed_end = compressed_start + compressed_size_hdr
	
	# Store the compressed zlib stream contents
	compressed_data = zlib_data[compressed_start:compressed_end]
	
	# Check if the compressed zlib stream is complete, based on header
	if len(compressed_data) != compressed_size_hdr :
		print('\n%sError: Incomplete Dell PFS ZLIB section data (Header)!' % (' ' * padd))
		is_zlib_error = True
	
	# Store the PFS ZLIB section footer contents (16 bytes)
	footer_data = zlib_data[compressed_end:compressed_end + 0x10]
	
	# Search input section for PFS ZLIB section footer
	pfs_zlib_footer_match = pfs_zlib_footer.search(footer_data)
	
	# Check if PFS ZLIB section footer was found in the section
	if not pfs_zlib_footer_match :
		print('\n%sError: This Dell PFS ZLIB section is corrupted!' % (' ' * padd))
		is_zlib_error = True
	
	# Check if the PFS ZLIB section footer Checksum XOR 8 is valid
	if chk_xor_8(footer_data[:0xF], 0) != footer_data[0xF] :
		print('\n%sError: Invalid Dell PFS ZLIB section Footer Checksum!' % (' ' * padd))
		is_zlib_error = True
	
	# Store the compressed zlib stream size from the footer contents
	compressed_size_ftr = int.from_bytes(footer_data[:0x4], 'little')
	
	# Check if the compressed zlib stream is complete, based on footer
	if compressed_size_ftr != compressed_size_hdr :
		print('\n%sError: Incomplete Dell PFS ZLIB section data (Footer)!' % (' ' * padd))
		is_zlib_error = True
	
	# Decompress PFS ZLIB section payload
	try :
		assert not is_zlib_error # ZLIB errors are critical
		section_data = zlib.decompress(compressed_data) # ZLIB decompression
	except :
		section_data = zlib_data # Fallback to raw ZLIB data upon critical error
	
	# Call the PFS Extract function on the decompressed PFS ZLIB Section
	pfs_extract(section_data, pfs_index, pfs_name, pfs_count, section_path, padd)
	
	# Show extraction complete message for each main PFS ZLIB Section
	print('\n%sExtracted Dell PFS %d >%s > %s section!' % (' ' * padd, pfs_index, pfs_name, section_name))

# Parse & Extract Dell PFS Volume
def pfs_extract(buffer, pfs_index, pfs_name, pfs_count, output_path, pfs_padd) :	
	if is_verbose : print('\n%sPFS Volume:' % (' ' * pfs_padd))
	
	# Get PFS Header Structure values
	pfs_hdr = get_struct(buffer, 0, PFS_DELL_HDR, None, pfs_padd + 4)
	
	# Validate that a PFS Header was parsed
	if pfs_hdr.Tag != b'PFS.HDR.' :
		msg_print(pfs_padd + 4, 'Error: PFS Header could not be found!')
		return # Critical error, abort
	
	# Show PFS Header Structure info
	if is_verbose : pfs_hdr.pfs_print(pfs_padd + 8)
	
	# Validate that a known PFS Header Version was encountered
	chk_hdr_ver(pfs_hdr.HeaderVersion, 'PFS', pfs_padd + 8)
	
	# Get PFS Payload Data
	pfs_payload = buffer[dpfs_hdr_size:dpfs_hdr_size + pfs_hdr.PayloadSize]
	
	# Parse all PFS Payload Entries/Components
	entry_index = 1 # Index number of each PFS Entry
	entry_start = 0 # Increasing PFS Entry starting offset
	entries_all = [] # Storage for each PFS Entry details
	filename_info = [] # Buffer for FileName Information Entry Data
	signature_info = [] # Buffer for Signature Information Entry Data
	pfs_entry_struct, pfs_entry_size = get_pfs_entry(pfs_payload, entry_start) # Get PFS Entry Info
	while len(pfs_payload[entry_start:entry_start + pfs_entry_size]) == pfs_entry_size :
		# Analyze PFS Entry Structure and get relevant info
		pfs_entry,entry_version,entry_guid,entry_data,entry_data_sig,entry_met,entry_met_sig,next_entry = \
		parse_pfs_entry(pfs_payload, entry_start, pfs_entry_size, pfs_entry_struct, None, 'PFS Entry', pfs_padd)
		
		entry_type = 'OTHER' # Adjusted later if PFS Entry is Zlib, PFAT, PFS Info, Model Info
		
		# Get PFS Information from the PFS Entry with GUID E0717CE3A9BB25824B9F0DC8FD041960 or B033CB16EC9B45A14055F80E4D583FD3
		if entry_guid in ['E0717CE3A9BB25824B9F0DC8FD041960','B033CB16EC9B45A14055F80E4D583FD3'] :
			filename_info = entry_data
			entry_type = 'NAME_INFO'
		
		# Get Model Information from the PFS Entry with GUID 6F1D619A22A6CB924FD4DA68233AE3FB
		elif entry_guid == '6F1D619A22A6CB924FD4DA68233AE3FB' :
			entry_type = 'MODEL_INFO'
		
		# Get Signature Information from the PFS Entry with GUID D086AFEE3ADBAEA94D5CED583C880BB7
		elif entry_guid == 'D086AFEE3ADBAEA94D5CED583C880BB7' :
			signature_info = entry_data
			entry_type = 'SIG_INFO'
			
		# Get Nested PFS from the PFS Entry with GUID 900FAE60437F3AB14055F456AC9FDA84
		elif entry_guid == '900FAE60437F3AB14055F456AC9FDA84' :
			entry_type = 'NESTED_PFS' # Nested PFS are usually zlib-compressed so it might change to 'ZLIB' later
		
		# Store all relevant PFS Entry details
		entries_all.append([entry_index, entry_guid, entry_version, entry_type, entry_data, entry_data_sig, entry_met, entry_met_sig])
		
		entry_index += 1 # Increase PFS Entry Index number for user-friendly output and name duplicates
		entry_start = next_entry # Next PFS Entry starts after PFS Entry Metadata Signature
	
	# Parse all PFS Information Entries/Descriptors
	info_start = 0 # Increasing PFS Information Entry starting offset
	info_all = [] # Storage for each PFS Information Entry details
	while len(filename_info[info_start:info_start + info_hdr_size]) == info_hdr_size :
		# Get PFS Information Header Structure info
		entry_info_hdr = get_struct(filename_info, info_start, PFS_INFO_HDR, None, pfs_padd + 8)
		
		# Show PFS Information Header Structure info
		if is_verbose : entry_info_hdr.pfs_print(pfs_padd + 8)
		
		# Validate that a known PFS Information Header Version was encountered
		if entry_info_hdr.HeaderVersion != 1 :
			msg_print(pfs_padd + 8, 'Error: Unknown PFS Information Header Version %d!' % entry_info_hdr.HeaderVersion)
			break # Skip PFS Information Entries/Descriptors in case of unknown PFS Information Header Version
		
		# Get PFS Information Header GUID in Big Endian format to match each Info to the equivalent stored PFS Entry details
		entry_guid = '%0.*X' % (0x10 * 2, int.from_bytes(entry_info_hdr.GUID, 'little'))
		
		# Get PFS FileName Structure values
		entry_info_mod = get_struct(filename_info, info_start + info_hdr_size, PFS_NAME_HDR, None, pfs_padd + 8)
		
		# Show PFS FileName Structure info
		if is_verbose : entry_info_mod.pfs_print(pfs_padd + 12)
		
		# The PFS FileName Structure is not complete by itself. The size of the last field (Entry Name) is determined from
		# CharacterCount multiplied by 2 due to usage of UTF-16 2-byte Characters. Any Entry Name leading and/or trailing
		# space/null characters are stripped and common Windows reserved/illegal filename characters are replaced
		name_start = info_start + info_hdr_size + name_hdr_size # PFS Entry's FileName start offset
		name_size = entry_info_mod.CharacterCount * 2 # PFS Entry's FileName buffer total size
		name_data = filename_info[name_start:name_start + name_size] # PFS Entry's FileName buffer
		entry_name = re.sub(win_char_bad, '_', name_data.decode('utf-16').strip()) # PFS Entry's FileName value
		
		# Show PFS FileName Name info (padding matches the one from PFS FileName Structure info)
		if is_verbose : print('%sPayload Name%s: %s' % (' ' * (pfs_padd + 12), ' ' * 4, entry_name))
		
		# Get PFS FileName Version string via "Version" and "VersionType" fields
		# PFS FileName Version string must be preferred over PFS Entry's Version
		entry_version = get_entry_ver(entry_info_mod.Version, entry_info_mod.VersionType, pfs_padd + 12)
		
		# Store all relevant PFS FileName details
		info_all.append([entry_guid, entry_name, entry_version])
		
		# The next PFS Information Header starts after the calculated FileName size
		# Two space/null characters seem to always exist after each FileName value
		info_start += (info_hdr_size + name_hdr_size + name_size + 0x2)
	
	# Parse Nested PFS Metadata when its PFS Information Entry is missing
	for index in range(len(entries_all)) :
		if entries_all[index][3] == 'NESTED_PFS' and not filename_info :
			entry_guid = entries_all[index][1] # Nested PFS Entry GUID in Big Endian format
			entry_metadata = entries_all[index][6] # Use Metadata as PFS Information Entry
			
			# When PFS Information Entry exists, Nested PFS Metadata contains only Model IDs
			# When it's missing, the Metadata structure is large and contains equivalent info
			if len(entry_metadata) >= meta_hdr_size :
				# Get Nested PFS Metadata Structure values
				entry_info = get_struct(entry_metadata, 0, PFS_META_HDR, None, pfs_padd + 4)
				
				# Show Nested PFS Metadata Structure info
				if is_verbose : entry_info.pfs_print(pfs_padd + 8)
				
				# As Nested PFS Entry Name, we'll use the actual PFS File Name
				# Replace common Windows reserved/illegal filename characters
				entry_name = re.sub(win_char_bad, '_', entry_info.FileName.decode('utf-8').strip('.exe'))
				
				# As Nested PFS Entry Version, we'll use the actual PFS File Version
				entry_version = entry_info.FileVersion.decode('utf-8')
				
				# Store all relevant Nested PFS Metadata/Information details
				info_all.append([entry_guid, entry_name, entry_version])
				
				# Re-set Nested PFS Entry Version from Metadata
				entries_all[index][2] = entry_version
	
	# Parse all PFS Signature Entries/Descriptors
	sign_start = 0 # Increasing PFS Signature Entry starting offset
	while len(signature_info[sign_start:sign_start + info_hdr_size]) == info_hdr_size :
		# Get PFS Information Header Structure info
		entry_info_hdr = get_struct(signature_info, sign_start, PFS_INFO_HDR, None, pfs_padd + 8)
		
		# Show PFS Information Header Structure info
		if is_verbose : entry_info_hdr.pfs_print(pfs_padd + 8)
		
		# Validate that a known PFS Information Header Version was encountered
		if entry_info_hdr.HeaderVersion != 1 :
			msg_print(pfs_padd + 8, 'Error: Unknown PFS Information Header Version %d!' % entry_info_hdr.HeaderVersion)
			break # Skip PFS Signature Entries/Descriptors in case of unknown Header Version
		
		# PFS Signature Entries/Descriptors have PFS_INFO_HDR + PFS_ENTRY_R* + Sign Size [0x2] + Sign Data [Sig Size]
		pfs_entry_struct, pfs_entry_size = get_pfs_entry(signature_info, sign_start + info_hdr_size) # Get PFS Entry Info
		
		# Get PFS Entry Header Structure info
		entry_hdr = get_struct(signature_info, sign_start + info_hdr_size, pfs_entry_struct, None, pfs_padd + 8)
		
		# Show PFS Information Header Structure info
		if is_verbose : entry_hdr.pfs_print(pfs_padd + 12)
		
		# Show PFS Signature Size & Data (after PFS_ENTRY_R*)
		sign_info_start = sign_start + info_hdr_size + pfs_entry_size
		sign_size = int.from_bytes(signature_info[sign_info_start:sign_info_start + 0x2], 'little')
		sign_data_raw = signature_info[sign_info_start + 0x2:sign_info_start + 0x2 + sign_size]
		sign_data_txt = '%0.*X' % (sign_size * 2, int.from_bytes(sign_data_raw, 'little'))
		if is_verbose :
			print('\n%sSignature Information:\n' % (' ' * (pfs_padd + 8)))
			print('%sSignature Size : 0x%X' % (' ' * (pfs_padd + 12), sign_size))
			print('%sSignature Data : %s [...]' % (' ' * (pfs_padd + 12), sign_data_txt[:32]))
		
		# The next PFS Signature Entry/Descriptor starts after the previous Signature Data
		sign_start += (info_hdr_size + pfs_entry_size + 0x2 + sign_size)
		
	# Parse each PFS Entry Data for special types (zlib or PFAT)
	for index in range(len(entries_all)) :
		entry_data = entries_all[index][4] # Get PFS Entry Data
		entry_type = entries_all[index][3] # Get PFS Entry Type
		
		# Very small PFS Entry Data cannot be of special type
		if len(entry_data) < dpfs_hdr_size : continue
		
		# Check if PFS Entry contains zlib-compressed sub-PFS Volume
		pfs_zlib_offsets = get_section_offsets(entry_data)
		
		# Check if PFS Entry contains sub-PFS Volume with PFAT Payload
		is_pfat = False # Initial PFAT state for sub-PFS Entry
		_, pfat_entry_size = get_pfs_entry(entry_data, dpfs_hdr_size) # Get possible PFS PFAT Entry Size
		pfat_hdr_off = dpfs_hdr_size + pfat_entry_size # Possible PFAT Header starts after PFS Header & Entry
		pfat_entry_hdr = get_struct(entry_data, 0, PFS_DELL_HDR, None, pfs_padd + 8) # Possible PFS PFAT Entry
		if len(entry_data) - pfat_hdr_off >= pfat_hdr_size :
			pfat_hdr = get_struct(entry_data, pfat_hdr_off, PFS_PFAT_HDR, [0], pfs_padd + 8)
			is_pfat = bytes(pfat_hdr.PlatformID).startswith((b'Dell',b'DELL'))
		
		# Parse PFS Entry which contains sub-PFS Volume with PFAT Payload
		if pfat_entry_hdr.Tag == b'PFS.HDR.' and is_pfat :
			entry_type = 'PFAT' # Re-set PFS Entry Type from OTHER to PFAT, to use such info afterwards
			
			entry_data = parse_pfat_pfs(pfat_entry_hdr, entry_data, pfs_padd) # Parse sub-PFS PFAT Volume
		
		# Parse PFS Entry which contains zlib-compressed sub-PFS Volume
		elif pfs_zlib_offsets :
			entry_type = 'ZLIB' # Re-set PFS Entry Type from OTHER to ZLIB, to use such info afterwards
			pfs_count += 1 # Increase the count/index of parsed main PFS structures by one
			
			# Parse each sub-PFS ZLIB Section
			for offset in pfs_zlib_offsets :				
				# Get the Name of the zlib-compressed full PFS structure via the already stored PFS Information
				# The zlib-compressed full PFS structure(s) are used to contain multiple FW (CombineBiosNameX)
				# When zlib-compressed full PFS structure(s) exist within the main/first full PFS structure,
				# its PFS Information should contain their names (CombineBiosNameX). Since the main/first
				# full PFS structure has count/index 1, the rest start at 2+ and thus, their PFS Information
				# names can be retrieved in order by subtracting 2 from the main/first PFS Information values
				sub_pfs_name = ' %s v%s' % (info_all[pfs_count - 2][1], info_all[pfs_count - 2][2]) if info_all else ' UNKNOWN'
				
				# Set the sub-PFS output path (create sub-folders for each sub-PFS and its ZLIB sections)
				sub_pfs_path = os.path.join(output_path, str(pfs_count) + sub_pfs_name)
				
				# Recursively call the PFS ZLIB Section Parser function for the sub-PFS Volume (pfs_index = pfs_count)
				pfs_section_parse(entry_data, offset, sub_pfs_path, sub_pfs_name, pfs_count, pfs_count, True, pfs_padd + 4)
			
		entries_all[index][4] = entry_data # Adjust PFS Entry Data after parsing PFAT (same ZLIB raw data, not stored afterwards)
		entries_all[index][3] = entry_type # Adjust PFS Entry Type from OTHER to PFAT or ZLIB (ZLIB is ignored at file extraction)
		
	# Name & Store each PFS Entry/Component Data, Data Signature, Metadata, Metadata Signature
	for entry_index in range(len(entries_all)) :
		file_index = entries_all[entry_index][0]
		file_guid = entries_all[entry_index][1]
		file_version = entries_all[entry_index][2]
		file_type = entries_all[entry_index][3]
		file_data = entries_all[entry_index][4]
		file_data_sig = entries_all[entry_index][5]
		file_meta = entries_all[entry_index][6]
		file_meta_sig = entries_all[entry_index][7]
		
		# Give Names to special PFS Entries, not covered by PFS Information
		if file_type == 'MODEL_INFO' :
			file_name = 'Model Information'
		elif file_type == 'NAME_INFO' :
			file_name = 'Filename Information'
			if not is_advanced : continue # Don't store Filename Information in non-advanced user mode
		elif file_type == 'SIG_INFO' :
			file_name = 'Signature Information'
			if not is_advanced : continue # Don't store Signature Information in non-advanced user mode
		else :
			file_name = ''
		
		# Most PFS Entry Names & Versions are found at PFS Information via their GUID
		# Version can be found at PFS_ENTRY_R* but prefer PFS Information when possible
		for info_index in range(len(info_all)) :
			info_guid = info_all[info_index][0]
			info_name = info_all[info_index][1]
			info_version = info_all[info_index][2]
			
			# Give proper Name & Version info if Entry/Information GUIDs match
			if info_guid == file_guid :
				file_name = info_name
				file_version = info_version
				
				info_all[info_index][0] = 'USED' # PFS with zlib-compressed sub-PFS use the same GUID
				break # Break at 1st Name match to not rename again from next zlib-compressed sub-PFS with the same GUID
		
		# For both advanced & non-advanced users, the goal is to store final/usable files only
		# so empty or intermediate files such as sub-PFS, PFS w/ PFAT or zlib-PFS are skipped
		# Main/First PFS CombineBiosNameX Metadata files must be kept for accurate Model Information
		# All users should check these files in order to choose the correct CombineBiosNameX modules
		write_files = [] # Initialize list of output PFS Entry files to be written/extracted
		
		is_zlib = bool(file_type == 'ZLIB') # Determine if PFS Entry Data was zlib-compressed
		
		if file_data and not is_zlib : write_files.append([file_data, 'data']) # PFS Entry Data Payload
		if file_data_sig and is_advanced : write_files.append([file_data_sig, 'sign_data']) # PFS Entry Data Signature
		if file_meta and (is_zlib or is_advanced) : write_files.append([file_meta, 'meta']) # PFS Entry Metadata Payload
		if file_meta_sig and is_advanced : write_files.append([file_meta_sig, 'sign_meta']) # PFS Entry Metadata Signature
		
		# Write/Extract PFS Entry files
		for file in write_files :
			pfs_file_write(file[0], file[1], file_type, output_path, pfs_padd, pfs_index, pfs_name, file_index, file_name, file_version, output_path)
	
	# Get PFS Footer Data after PFS Header Payload
	pfs_footer = buffer[dpfs_hdr_size + pfs_hdr.PayloadSize:dpfs_hdr_size + pfs_hdr.PayloadSize + dpfs_ftr_size]
	
	# Analyze PFS Footer Structure
	chk_pfs_ftr(pfs_footer, pfs_payload, pfs_hdr.PayloadSize, 'PFS', pfs_padd)

# Analyze Dell PFS Entry Structure
def parse_pfs_entry(entry_buffer, entry_start, entry_size, entry_struct, struct_args, text, padd) :	
	# Get PFS Entry Structure values
	pfs_entry = get_struct(entry_buffer, entry_start, entry_struct, struct_args, padd + 4)
	
	# Show PFS Entry Structure info
	if is_verbose : pfs_entry.pfs_print(padd + 8)
	
	# Validate that a known PFS Entry Header Version was encountered
	chk_hdr_ver(pfs_entry.HeaderVersion, text, padd + 8)
	
	# Validate that the PFS Entry Reserved field is empty
	if pfs_entry.Reserved != 0 :
		msg_print(padd + 8, 'Error: Detected non-empty %s Reserved field!' % text)
	
	# Get PFS Entry Version string via "Version" and "VersionType" fields
	entry_version = get_entry_ver(pfs_entry.Version, pfs_entry.VersionType, padd + 8)
	
	# Get PFS Entry GUID in Big Endian format
	entry_guid = '%0.*X' % (0x10 * 2, int.from_bytes(pfs_entry.GUID, 'little'))
	
	# PFS Entry Data starts after the PFS Entry Structure
	entry_data_start = entry_start + entry_size
	entry_data_end = entry_data_start + pfs_entry.DataSize
	
	# PFS Entry Data Signature starts after PFS Entry Data
	entry_data_sig_start = entry_data_end
	entry_data_sig_end = entry_data_sig_start + pfs_entry.DataSigSize
	
	# PFS Entry Metadata starts after PFS Entry Data Signature
	entry_met_start = entry_data_sig_end 
	entry_met_end = entry_met_start + pfs_entry.DataMetSize
	
	# PFS Entry Metadata Signature starts after PFS Entry Metadata
	entry_met_sig_start = entry_met_end
	entry_met_sig_end = entry_met_sig_start + pfs_entry.DataMetSigSize
	
	entry_data = entry_buffer[entry_data_start:entry_data_end] # Store PFS Entry Data
	entry_data_sig = entry_buffer[entry_data_sig_start:entry_data_sig_end] # Store PFS Entry Data Signature
	entry_met = entry_buffer[entry_met_start:entry_met_end] # Store PFS Entry Metadata
	entry_met_sig = entry_buffer[entry_met_sig_start:entry_met_sig_end] # Store PFS Entry Metadata Signature
	
	return pfs_entry, entry_version, entry_guid, entry_data, entry_data_sig, entry_met, entry_met_sig, entry_met_sig_end

# Parse Dell PFS Volume with PFAT Payload
def parse_pfat_pfs(entry_hdr, entry_data, padd) :
	if is_verbose : print('\n%sPFS Volume:' % (' ' * (padd + 4)))
	
	# Show sub-PFS Header Structure Info
	if is_verbose : entry_hdr.pfs_print(padd + 12)
	
	# Validate that a known sub-PFS Header Version was encountered
	chk_hdr_ver(entry_hdr.HeaderVersion, 'sub-PFS', padd + 12)
	
	# Get sub-PFS Payload Data
	pfat_payload = entry_data[dpfs_hdr_size:dpfs_hdr_size + entry_hdr.PayloadSize]
	
	# Get sub-PFS Footer Data after sub-PFS Header Payload (must be retrieved at the initial entry_data, before PFAT parsing)
	pfat_footer = entry_data[dpfs_hdr_size + entry_hdr.PayloadSize:dpfs_hdr_size + entry_hdr.PayloadSize + dpfs_ftr_size]
	
	# Parse all sub-PFS Payload PFAT Entries
	pfat_data_all = [] # Storage for all sub-PFS PFAT Entries Order/Offset & Payload/Raw Data
	pfat_entry_start = 0 # Increasing sub-PFS PFAT Entry start offset
	pfat_entry_index = 0 # Increasing sub-PFS PFAT Entry count index
	_, pfs_entry_size = get_pfs_entry(pfat_payload, 0) # Get initial PFS PFAT Entry Size for loop
	while len(pfat_payload[pfat_entry_start:pfat_entry_start + pfs_entry_size]) == pfs_entry_size :
		# Get sub-PFS PFAT Entry Structure & Size info
		pfat_entry_struct, pfat_entry_size = get_pfs_entry(pfat_payload, pfat_entry_start)
		
		# Analyze sub-PFS PFAT Entry Structure and get relevant info
		pfat_entry,pfat_entry_version,pfat_entry_guid,pfat_entry_data,pfat_entry_data_sig,pfat_entry_met,pfat_entry_met_sig,pfat_next_entry = \
		parse_pfs_entry(pfat_payload, pfat_entry_start, pfat_entry_size, pfat_entry_struct, None, 'sub-PFS PFAT Entry', padd + 4)
		
		# Each sub-PFS PFAT Entry includes an AMI BIOS Guard (a.k.a. PFAT) block at the beginning
		# We need to parse the PFAT block and remove its contents from the final Payload/Raw Data
		pfat_hdr_off = pfat_entry_start + pfat_entry_size # PFAT block starts after PFS Entry
		
		# Get sub-PFS PFAT Header Structure values
		pfat_hdr = get_struct(pfat_payload, pfat_hdr_off, PFS_PFAT_HDR, [pfat_entry_index], padd + 12)
		
		# Show sub-PFS PFAT Header Structure info
		if is_verbose : pfat_hdr.pfs_print(padd + 16)
		
		# Get PFAT Header Flags (SFAM, ProtectEC, GFXMitDis, FTU, Reserved)
		pfat_flag_sig,_,_,_,_ = pfat_hdr.get_flags()
		
		pfat_script_start = pfat_hdr_off + pfat_hdr_size # PFAT Block Script Start
		pfat_script_end = pfat_script_start + pfat_hdr.ScriptSize # PFAT Block Script End
		pfat_script_data = pfat_payload[pfat_script_start:pfat_script_end] # PFAT Block Script Data
		pfat_payload_start = pfat_script_end # PFAT Block Payload Start (at Script end)
		pfat_payload_end = pfat_script_end + pfat_hdr.DataSize # PFAT Block Data End
		pfat_payload_data = pfat_payload[pfat_payload_start:pfat_payload_end] # PFAT Block Raw Data
		pfat_hdr_bgs_size = pfat_hdr_size + pfat_hdr.ScriptSize # PFAT Block Header & Script Size
		
		# The PFAT Script End should match the total Entry Data Size w/o PFAT block 
		if pfat_hdr_bgs_size != pfat_entry.DataSize - pfat_hdr.DataSize :
			msg_print(padd + 16, 'Error: Detected sub-PFS PFAT Entry Header & PFAT Size mismatch!')
		
		# Parse sub-PFS PFAT Signature, if applicable (only when PFAT Header > SFAM flag is set)
		if pfat_flag_sig and pfat_payload[pfat_payload_end:pfat_payload_end + pfat_sig_size] == pfat_sig_size :
			# Get sub-PFS PFAT Signature Structure values
			pfat_sig = get_struct(pfat_payload, pfat_payload_end, PFS_PFAT_SIG, [pfat_entry_index], padd + 12)
			
			# Show sub-PFS PFAT Signature Structure info
			if is_verbose : pfat_sig.pfs_print(padd + 16)
		
		# Show PFAT Script via BIOS Guard Script Tool
		# https://github.com/allowitsme/big-tool by Dmitry Frolov
		if is_verbose :
			print('\n%sPFAT Block %d Script:\n' % (' ' * (padd + 12), pfat_entry_index))
			is_opcode_div = len(pfat_script_data) % 8 == 0
			is_begin_end = pfat_script_data[:8] + pfat_script_data[-8:] == b'\x01' + b'\x00' * 7 + b'\xFF' + b'\x00' * 7
			if is_opcode_div and is_begin_end and is_bgst :
				pfat_script_decomp = BigScript(code_bytes=pfat_script_data)
				pfat_script_lines = pfat_script_decomp.to_string().replace('\t','    ').split('\n')
				for line in pfat_script_lines :
					spacing = ' ' * (padd + 16) if line.endswith(('begin','end',':')) else ' ' * (padd + 24)
					operands = [op for op in line.split(' ') if op != '']
					print(spacing + ('{:<12s}' + '{:<11s}' * (len(operands) - 1)).format(*operands))
			elif not is_opcode_div :
				print('%sError: Script not divisible by OpCode length!' % (' ' * (padd + 16)))
			elif not is_begin_end :
				print('%sError: Script lacks Begin and/or End OpCodes!' % (' ' * (padd + 16)))
			elif not is_bgst :
				print('%sError: BIOS Guard Script Tool dependency missing!' % (' ' * (padd + 16)))
		
		# The payload of sub-PFS PFAT Entries is not in proper order by default
		# We can get each payload's order from PFAT Script > OpCode #2 (set I0 imm)
		# PFAT Script OpCode #2 > Operand #3 stores the payload Offset in final image
		pfat_entry_off = int.from_bytes(pfat_script_data[0xC:0x10], 'little')
		
		# Parse sub-PFS PFAT Entry/Block Metadata
		if len(pfat_entry_met) >= pfat_met_size :
			# Get sub-PFS PFAT Metadata Structure values
			pfat_met = get_struct(pfat_entry_met, 0, PFS_PFAT_MET, [pfat_entry_index], padd + 12)
			
			# Show sub-PFS PFAT Metadata Structure info
			if is_verbose : pfat_met.pfs_print(padd + 16)
			
			# Another way to get each PFAT Entry payload's Order is from its Metadata at 0x8-0xC, if applicable
			# Check that the PFAT Entry payload Order/Offset from PFAT Script matches the one from PFAT Metadata
			if pfat_entry_off != pfat_met.OffsetBase :
				msg_print(padd + 16, 'Error: Detected sub-PFS PFAT Entry Metadata & PFAT Base Offset mismatch!')
				pfat_entry_off = pfat_met.OffsetBase # Prefer Offset from Metadata, in case PFAT Script differs
			
			# Check that the PFAT Entry payload Size from PFAT Header matches the one from PFAT Metadata
			if pfat_hdr.DataSize != pfat_met.BlockSize :
				msg_print(padd + 16, 'Error: Detected sub-PFS PFAT Entry Metadata & PFAT Block Size mismatch!')		
		
		# Get sub-PFS Entry Raw Data by subtracting PFAT Header & Script from PFAT Entry Data
		pfat_entry_data_raw = pfat_entry_data[pfat_hdr_bgs_size:]
		
		# The sub-PFS Entry Raw Data (w/o PFAT Header & Script) should match with the PFAT Block payload
		if pfat_entry_data_raw != pfat_payload_data :
			msg_print(padd + 16, 'Error: Detected sub-PFS PFAT Entry w/o PFAT & PFAT Block Data mismatch!')
			pfat_entry_data_raw = pfat_payload_data # Prefer Data from PFAT Block, in case PFAT Entry differs
		
		# Store each sub-PFS PFAT Entry Order/Offset and Payload/Raw Data (w/o PFAT)
		pfat_data_all.append((pfat_entry_off, pfat_entry_data_raw))
		
		pfat_entry_start = pfat_next_entry # Next sub-PFS PFAT Entry starts after sub-PFS Entry Metadata Signature
		
		pfat_entry_index += 1
	
	pfat_data_all.sort() # Sort all sub-PFS PFAT Entries payloads/data based on their Order/Offset
	
	entry_data = b'' # Initialize new sub-PFS Entry Data
	for pfat_data in pfat_data_all : entry_data += pfat_data[1] # Merge all sub-PFS PFAT Entry Payload/Raw into the final sub-PFS Entry Data
	
	# Verify that the Order/Offset of the last PFAT Entry w/ its Size matches the final sub-PFS Entry Data Size
	if len(entry_data) != pfat_data_all[-1][0] + len(pfat_data_all[-1][1]) :
		msg_print(padd + 8, 'Error: Detected sub-PFS PFAT Entry Buffer & Last Offset Size mismatch!')
	
	# Analyze sub-PFS Footer Structure
	chk_pfs_ftr(pfat_footer, pfat_payload, entry_hdr.PayloadSize, 'Sub-PFS', padd + 4)
	
	return entry_data

# Get Dell PFS Entry Structure & Size via its Version
def get_pfs_entry(buffer, offset) :
	pfs_entry_ver = int.from_bytes(buffer[offset + 0x10:offset + 0x14], 'little') # PFS Entry Version
	
	if pfs_entry_ver == 1 : return PFS_ENTRY_R1, ctypes.sizeof(PFS_ENTRY_R1)
	if pfs_entry_ver == 2 : return PFS_ENTRY_R2, ctypes.sizeof(PFS_ENTRY_R2)

	return PFS_ENTRY_R2, ctypes.sizeof(PFS_ENTRY_R2)

# Determine Dell PFS Entry Version string
def get_entry_ver(version_fields, version_types, msg_padd) :
	version = '' # Initialize Version string
	
	# Each Version Type (1 byte) determines the type of each Version Value (2 bytes)
	# Version Type 'N' is Number, 'A' is Text and ' ' is Empty/Unused
	for idx in range(len(version_fields)) :
		eol = '' if idx == len(version_fields) - 1 else '.'
		
		if version_types[idx] == 65 : version += '%X%s' % (version_fields[idx], eol) # 0x41 = ASCII
		elif version_types[idx] == 78 : version += '%d%s' % (version_fields[idx], eol) # 0x4E = Number
		elif version_types[idx] in (0, 32) : version = version.strip('.') # 0x00 or 0x20 = Unused
		else :
			version += '%X%s' % (version_fields[idx], eol) # Unknown
			msg_print(msg_padd, 'Error: Unknown PFS Entry Version Type 0x%0.2X!' % version_types[idx])
			
	return version

# Check if Dell PFS Header Version is known
def chk_hdr_ver(version, text, padd) :
	if version in (1,2) : return
	
	msg_print(padd, 'Error: Unknown %s Header Version %d!' % (text, version))

# Analyze Dell PFS Footer Structure
def chk_pfs_ftr(footer_buffer, data_buffer, data_size, text, padd) :	
	# Get PFS Footer Structure values
	pfs_ftr = get_struct(footer_buffer, 0, PFS_DELL_FTR, None, padd + 8)
	
	# Validate that a PFS Footer was parsed
	if pfs_ftr.Tag == b'PFS.FTR.' :
		# Show PFS Footer Structure info
		if is_verbose : pfs_ftr.pfs_print(padd + 8)
	else :
		msg_print(padd + 4, 'Error: %s Footer could not be found!' % text)
	
	# Validate that PFS Header Payload Size matches the one at PFS Footer
	if data_size != pfs_ftr.PayloadSize :
		msg_print(padd + 4, 'Error: %s Header & Footer Payload Size mismatch!' % text)
	
	# Calculate the PFS Payload Data CRC-32 w/ Vector 0
	pfs_ftr_crc = ~zlib.crc32(data_buffer, 0) & 0xFFFFFFFF
	
	# Validate PFS Payload Data Checksum via PFS Footer
	if pfs_ftr.Checksum != pfs_ftr_crc :
		msg_print(padd + 4, 'Error: Invalid %s Footer Payload Checksum!' % text)

# Write/Extract Dell PFS Entry Files (Data, Metadata, Signature)
def pfs_file_write(bin_buff, bin_name, bin_type, out_path, padd, pfs_idx, pfs_name, file_idx, file_name, file_ver, output_path) :
	full_name = '%d%s -- %d %s v%s' % (pfs_idx, pfs_name, file_idx, file_name, file_ver) # Full PFS Entry Name
	safe_name = re.sub(win_char_bad, '_', full_name) # Replace common Windows reserved/illegal filename characters
	
	# Store Data/Metadata Signature (advanced users only)
	if bin_name.startswith('sign') :
		final_name = '%s.%s.sig' % (safe_name, bin_name.split('_')[1])
		final_path = os.path.join(output_path, final_name)
		
		with open(final_path, 'wb') as pfs_out : pfs_out.write(bin_buff) # Write final Data/Metadata Signature
		
		return # Skip further processing for Signatures
	
	# Store Data/Metadata Payload
	bin_ext = '.%s.bin' % bin_name if is_advanced else '.bin' # Simpler Data/Metadata Extension for non-advanced users
	
	# Some Data may be Text or XML files with useful information for non-advanced users
	is_text,final_data,file_ext,write_mode = bin_is_text(bin_buff, bin_type, bin_name == 'meta', is_advanced, is_verbose, padd)
	
	final_name = '%s%s' % (safe_name, bin_ext[:-4] + file_ext if is_text else bin_ext)
	final_path = os.path.join(out_path, final_name)
	
	with open(final_path, write_mode) as pfs_out : pfs_out.write(final_data) # Write final Data/Metadata Payload

# Check if Dell PFS Entry file/data is Text/XML and Convert
def bin_is_text(buffer, file_type, is_metadata, is_advanced, is_verbose, pfs_padd) :
	is_text = False
	write_mode = 'wb'
	extension = '.bin'
	buffer_in = buffer
	
	if b',END' in buffer[-0x8:] : # Text Type 1
		is_text = True
		write_mode = 'w'
		extension = '.txt'
		buffer = buffer.decode('utf-8').split(',END')[0].replace(';','\n')
	elif buffer.startswith(b'VendorName=Dell') : # Text Type 2
		is_text = True
		write_mode = 'w'
		extension = '.txt'
		buffer = buffer.split(b'\x00')[0].decode('utf-8').replace(';','\n')
	elif b'<Rimm x-schema="' in buffer[:0x50] : # XML Type
		is_text = True
		write_mode = 'w'
		extension = '.xml'
		buffer = buffer.decode('utf-8')
	elif file_type in ('NESTED_PFS','ZLIB') and is_metadata and len(buffer) == meta_hdr_size : # Text Type 3
		is_text = True
		write_mode = 'w'
		extension = '.txt'
		buffer = get_struct(buffer, 0, PFS_META_HDR, None, pfs_padd + 8).pfs_write()
	
	# Show Model/PCR XML Information, if applicable
	if is_verbose and is_text and not is_metadata : # Metadata is shown at initial PFS_META_HDR analysis
		print('\n%sPFS %s Information:\n' % (' ' * (pfs_padd + 8), {'.txt': 'Model', '.xml': 'PCR XML'}[extension]))
		_ = [print('%s%s' % (' ' * (pfs_padd + 12), line.strip('\r'))) for line in buffer.split('\n') if line]
	
	# Only for non-advanced users due to signature (.sig) invalidation
	if is_advanced : return False, buffer_in, '.bin', 'wb'
	
	return is_text, buffer, extension, write_mode

# Calculate Checksum XOR 8 of data
def chk_xor_8(data, init_value) :
	value = init_value
	for byte in data : value = value ^ byte
	value ^= 0x0
	
	return value

# Show (padded) Message/Log
def msg_print(padd, msg) :
	print('\n%s%s' % (' ' * (padd if is_verbose else 4), msg))

# Process ctypes Structure Classes
# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
def get_struct(buffer, start_offset, class_name, param_list, msg_padd) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = buffer[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= len(buffer)) or (fit_len < struct_len) :
		msg_print(msg_padd, 'Error: Invalid offset 0x%X at %s, possibly incomplete buffer!' % (start_offset, class_name.__name__))
		sys.exit(1) # Critical error
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure

# Get absolute file path (argparse object)
def get_absolute_path(argparse_path) :
	if not argparse_path :
		absolute_path = get_script_dir() # Use input file directory if no user path is specified
	else :
		# Check if user specified path is absolute, otherwise convert it to input file relative
		if pathlib.Path(argparse_path).is_absolute() : absolute_path = argparse_path
		else : absolute_path = os.path.join(get_script_dir(), argparse_path)
	
	return absolute_path

# Get list of files from absolute path
def get_path_files(abs_path) :
	file_list = [] # Initialize list of files
	
	# Traverse input absolute path
	for root,_,files in os.walk(abs_path):
		file_list = [os.path.join(root, name) for name in files]
	
	return file_list

# Get python script working directory
# https://stackoverflow.com/a/22881871 by jfs
def get_script_dir(follow_symlinks=True) :
	if getattr(sys, 'frozen', False) :
		path = os.path.abspath(sys.executable)
	else :
		path = inspect.getabsfile(get_script_dir)
	if follow_symlinks :
		path = os.path.realpath(path)

	return os.path.dirname(path)

# Pause after any unexpected Python exception
# https://stackoverflow.com/a/781074 by Torsten Marek
def show_exception_and_exit(exc_type, exc_value, tb) :
	if exc_type is KeyboardInterrupt :
		print('\n')
	else :
		print('\nError: %s crashed, please report the following:\n' % title)
		traceback.print_exception(exc_type, exc_value, tb)
		if not bool(args.auto_exit) : input('\nPress enter to exit')
	
	sys.exit(1) # Crash exceptions are critical

# Show script title
print('\n' + title)

# Set console/shell window title
user_os = sys.platform
if user_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(title)
elif user_os.startswith('linux') or user_os == 'darwin' or user_os.find('bsd') != -1 : sys.stdout.write('\x1b]2;' + title + '\x07')

# Set argparse Arguments
parser = argparse.ArgumentParser()
parser.add_argument('images', type=argparse.FileType('r'), nargs='*')
parser.add_argument('-a', '--advanced', help='extract in advanced user mode', action='store_true')
parser.add_argument('-v', '--verbose', help='show PFS structure information', action='store_true')
parser.add_argument('-e', '--auto-exit', help='skip press enter to exit prompts', action='store_true')
parser.add_argument('-o', '--output-dir', help='extract in given output directory')
parser.add_argument('-i', '--input-dir', help='extract from given input directory')
args = parser.parse_args()

# Set pause-able Python exception handler (must be after args)
sys.excepthook = show_exception_and_exit

# Get ctypes Structure Sizes
dpfs_hdr_size = ctypes.sizeof(PFS_DELL_HDR)
dpfs_ftr_size = ctypes.sizeof(PFS_DELL_FTR)
info_hdr_size = ctypes.sizeof(PFS_INFO_HDR)
name_hdr_size = ctypes.sizeof(PFS_NAME_HDR)
meta_hdr_size = ctypes.sizeof(PFS_META_HDR)
pfat_hdr_size = ctypes.sizeof(PFS_PFAT_HDR)
pfat_sig_size = ctypes.sizeof(PFS_PFAT_SIG)
pfat_met_size = ctypes.sizeof(PFS_PFAT_MET)

# The Dell ThinOS PKG update images usually contain multiple sections. Each section starts with a
# 0x30 sized header, which begins with pattern 72135500. The section length is found at 0x10-0x14
# and its (optional) MD5 hash at 0x20-0x30. The section data can be raw or LZMA2 (7zXZ) compressed.
# The LZMA2 section includes the actual Dell PFS update image, so it needs to be decompressed first.
lzma_pkg_header = re.compile(br'\x72\x13\x55\x00.{45}\x37\x7A\x58\x5A', re.DOTALL)

# The Dell PFS update images usually contain multiple sections. Each section is zlib-compressed
# with header pattern ********++EEAA761BECBB20F1E651--789C where ******** is the zlib stream size,
# ++ is the section type and -- the header Checksum XOR 8. The "Firmware" section has type AA and its
# files are stored in PFS format. The "Utility" section has type BB and its files are stored in PFS, 
# BIN or 7z formats. Each section is followed by the footer pattern ********EEAAEE8F491BE8AE143790--
# where ******** is the zlib stream size and ++ the footer Checksum XOR 8.
pfs_zlib_header = re.compile(br'\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78\x9C', re.DOTALL)
pfs_zlib_footer = re.compile(br'\xEE\xAA\xEE\x8F\x49\x1B\xE8\xAE\x14\x37\x90')

# Dell PFS ZLIB Section Type & Name Dictionary
section_dict = {0xAA : 'Firmware', 0xBB : 'Utilities'}

# Illegal/Reserved Windows filename characters
win_char_bad = r'[\\/*?:"<>|]'

# Initialize Dell PFS input file list
pfs_input_images = []

# Process input files
if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	if args.input_dir :
		input_path_user = get_absolute_path(args.input_dir)
		pfs_input_images = get_path_files(input_path_user)
	else :
		pfs_input_images = [image.name for image in args.images]
else :
	# Script w/o parameters
	input_path_user = get_absolute_path(input('\nEnter input directory path: '))
	pfs_input_images = get_path_files(input_path_user)

# Initialize global variables
exit_code = len(pfs_input_images) # Initialize exit code with input file count
is_advanced = bool(args.advanced) # Set Advanced user mode optional argument
is_verbose = bool(args.verbose) # Set Verbose output mode optional argument

# Initialize Dell PFS Update Extractor
if __name__ == '__main__':
	sys.exit(main(exit_code, pfs_input_images))