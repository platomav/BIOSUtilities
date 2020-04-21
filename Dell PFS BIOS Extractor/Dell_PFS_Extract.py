#!/usr/bin/env python3

"""
Dell PFS Extract
Dell PFS BIOS Extractor
Copyright (C) 2019-2020 Plato Mavropoulos
Inspired from https://github.com/LongSoft/PFSExtractor-RS by Nikolaj Schlej
"""

title = 'Dell PFS BIOS Extractor v4.0'

import os
import re
import sys
import zlib
import shutil
import struct
import ctypes
import argparse
import traceback

# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

class PFS_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('Tag',					char*8),		# 0x00
		('HeaderVersion',		uint32_t),		# 0x08
		('PayloadSize',			uint32_t),		# 0x0C
		# 0x10
	]
	
	def pfs_print(self) :		
		print('\nPFS Header:\n')
		print('Tag            : %s' % self.Tag.decode('utf-8'))
		print('HeaderVersion  : %d' % self.HeaderVersion)
		print('PayloadSize    : 0x%X' % self.PayloadSize)
		
class PFS_FTR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('PayloadSize',			uint32_t),		# 0x00
		('Checksum',			uint32_t),		# 0x04 ~CRC32 w/ Vector 0
		('Tag',					char*8),		# 0x08
		# 0x10
	]
	
	def pfs_print(self) :		
		print('\nPFS Footer:\n')
		print('PayloadSize    : 0x%X' % self.PayloadSize)
		print('Checksum       : 0x%0.8X' % self.Checksum)
		print('Tag            : %s' % self.Tag.decode('utf-8'))

class PFS_ENTRY(ctypes.LittleEndianStructure) :
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
	
	def pfs_print(self) :
		GUID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.GUID))
		VersionType = ''.join('%0.4X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.VersionType))
		Version = ''.join('%0.4X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Version))
		Unknown = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown))
		
		print('\nPFS Entry:\n')
		print('GUID           : %s' % GUID)
		print('HeaderVersion  : %d' % self.HeaderVersion)
		print('VersionType    : %s' % VersionType)
		print('Version        : %s' % Version)
		print('Reserved       : 0x%X' % self.Reserved)
		print('DataSize       : 0x%X' % self.DataSize)
		print('DataSigSize    : 0x%X' % self.DataSigSize)
		print('DataMetSize    : 0x%X' % self.DataMetSize)
		print('DataMetSigSize : 0x%X' % self.DataMetSigSize)
		print('Unknown        : %s' % Unknown)
		
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
	
	def pfs_print(self) :
		GUID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.GUID))
		VersionType = ''.join('%0.4X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.VersionType))
		Version = ''.join('%0.4X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Version))
		Unknown = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Unknown))
		
		print('\nPFS Entry:\n')
		print('GUID           : %s' % GUID)
		print('HeaderVersion  : %d' % self.HeaderVersion)
		print('VersionType    : %s' % VersionType)
		print('Version        : %s' % Version)
		print('Reserved       : 0x%X' % self.Reserved)
		print('DataSize       : 0x%X' % self.DataSize)
		print('DataSigSize    : 0x%X' % self.DataSigSize)
		print('DataMetSize    : 0x%X' % self.DataMetSize)
		print('DataMetSigSize : 0x%X' % self.DataMetSigSize)
		print('Unknown        : %s' % Unknown)
		
class PFS_INFO(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('HeaderVersion',		uint32_t),		# 0x00
		('GUID',				uint32_t*4),	# 0x04 Little Endian
		('Version',				uint16_t*4),	# 0x14
		('VersionType',			uint8_t*4),		# 0x1C
		('CharacterCount',		uint16_t),		# 0x20 UTF-16 2-byte Characters
		# 0x22
	]
	
	def pfs_print(self) :
		GUID = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.GUID))
		Version = ''.join('%0.4X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.Version))
		VersionType = ''.join('%0.2X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(self.VersionType))
		
		print('\nPFS Information:\n')
		print('HeaderVersion  : %d' % self.HeaderVersion)
		print('GUID           : %s' % GUID)
		print('Version        : %s' % Version)
		print('VersionType    : %s' % VersionType)
		print('CharacterCount : %d' % (self.CharacterCount * 2))
		
class METADATA_INFO(ctypes.LittleEndianStructure) :
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
	
	def pfs_print(self) :
		print('\nMetadata Information:\n')
		print('Model IDs      : %s' % self.ModelIDs.decode('utf-8').strip(',END'))
		print('File Name      : %s' % self.FileName.decode('utf-8'))
		print('File Version   : %s' % self.FileVersion.decode('utf-8'))
		print('Date           : %s' % self.Date.decode('utf-8'))
		print('Brand          : %s' % self.Brand.decode('utf-8'))
		print('Model File     : %s' % self.ModelFile.decode('utf-8'))
		print('Model Name     : %s' % self.ModelName.decode('utf-8'))
		print('Model Version  : %s' % self.ModelVersion.decode('utf-8'))
		
	def pfs_write(self) :
		return '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' % (self.ModelIDs.decode('utf-8').strip(',END'), self.FileName.decode('utf-8'),
				self.FileVersion.decode('utf-8'), self.Date.decode('utf-8'), self.Brand.decode('utf-8'), self.ModelFile.decode('utf-8'),
				self.ModelName.decode('utf-8'), self.ModelVersion.decode('utf-8'))

# Dell PFS.HDR. Extractor
# noinspection PyUnusedLocal
def pfs_extract(buffer, pfs_index, pfs_name, pfs_count) :
	# Get PFS Header Structure values
	pfs_hdr = get_struct(buffer, 0, PFS_HDR)
	
	# Validate that a PFS Header was parsed
	if pfs_hdr.Tag != b'PFS.HDR.' :
		print('\n    Error: PFS Header could not be found!')
		return # Critical error, abort
		
	# Validate that a known PFS Header Version was encountered
	if pfs_hdr.HeaderVersion not in (1,2) :
		print('\n    Error: Unknown PFS Header Version %d!' % pfs_hdr.HeaderVersion)
	
	# Get PFS Footer Data after PFS Header Payload
	footer = buffer[pfs_header_size + pfs_hdr.PayloadSize:pfs_header_size + pfs_hdr.PayloadSize + pfs_footer_size]
	
	# Get PFS Footer Structure values
	pfs_ftr = pfs_hdr = get_struct(footer, 0, PFS_FTR)
	
	# Validate that a PFS Footer was parsed
	if pfs_ftr.Tag != b'PFS.FTR.' :
		print('\n    Error: PFS Footer could not be found!')
	
	# Validate that the PFS Header Payload Size matches the one at the PFS Footer
	if pfs_hdr.PayloadSize != pfs_ftr.PayloadSize :
		print('\n    Error: PFS Header & Footer Payload Size mismatch!')
		
	# Get PFS Payload Data
	payload = buffer[pfs_header_size:pfs_header_size + pfs_hdr.PayloadSize]
		
	# Calculate the PFS Payload Data CRC-32 w/ Vector 0 Checksum
	footer_checksum = ~zlib.crc32(payload, 0) & 0xFFFFFFFF
	
	# Validate PFS Payload Data Checksum via the PFS Footer
	if pfs_ftr.Checksum != footer_checksum :
		print('\n    Error: Invalid PFS Footer Payload Checksum!')
	
	# Parse all PFS Payload Entries/Components
	entry_index = 1 # Index number of each PFS Entry
	entry_start = 0 # Increasing PFS Entry starting offset
	entries_all = [] # Storage for each PFS Entry details
	pfs_info = [] # Buffer for PFS Information Entry Data
	pfs_entry_struct, pfs_entry_size = get_pfs_entry(payload, entry_start)
	while len(payload[entry_start:entry_start + pfs_entry_size]) == pfs_entry_size :
		# Get PFS Entry Structure values
		pfs_entry = get_struct(payload, entry_start, pfs_entry_struct)
		
		# Validate that a known PFS Entry Header Version was encountered
		if pfs_entry.HeaderVersion not in (1,2) :
			print('\n    Error: Unknown PFS Entry Header Version %d!' % pfs_entry.HeaderVersion)
		
		# Validate that the PFS Entry Reserved field is empty
		if pfs_entry.Reserved != 0 :
			print('\n    Error: Detected non-empty PFS Entry Reserved field!')
		
		# Get PFS Entry Version string via "Version" and "VersionType" fields
		entry_version = get_version(pfs_entry.Version, pfs_entry.VersionType)
		
		# Get PFS Entry GUID in Big Endian format
		entry_guid = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(pfs_entry.GUID))
		
		# PFS Entry Data starts after the PFS Entry Structure
		entry_data_start = entry_start + pfs_entry_size
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
		
		entry_data = payload[entry_data_start:entry_data_end] # Store PFS Entry Data
		entry_data_sig = payload[entry_data_sig_start:entry_data_sig_end] # Store PFS Entry Data Signature
		entry_met = payload[entry_met_start:entry_met_end] # Store PFS Entry Metadata
		entry_met_sig = payload[entry_met_sig_start:entry_met_sig_end] # Store PFS Entry Metadata Signature
		
		entry_type = 'OTHER' # Adjusted later if PFS Entry is Zlib, Chunks, PFS Info, Model Info
		
		# Get PFS Information from the PFS Entry with GUID E0717CE3A9BB25824B9F0DC8FD041960 or B033CB16EC9B45A14055F80E4D583FD3
		if entry_guid in ['E0717CE3A9BB25824B9F0DC8FD041960','B033CB16EC9B45A14055F80E4D583FD3'] :
			pfs_info = entry_data
			entry_type = 'PFS_INFO'
		
		# Get Model Information from the PFS Entry with GUID 6F1D619A22A6CB924FD4DA68233AE3FB
		elif entry_guid == '6F1D619A22A6CB924FD4DA68233AE3FB' :
			entry_type = 'MODEL_INFO'
			
		# Get Nested PFS from the PFS Entry with GUID 900FAE60437F3AB14055F456AC9FDA84
		elif entry_guid == '900FAE60437F3AB14055F456AC9FDA84' :
			entry_type = 'NESTED_PFS' # Nested PFS are usually zlib-compressed so it might change to 'ZLIB' later
		
		# Store all relevant PFS Entry details
		entries_all.append([entry_index, entry_guid, entry_version, entry_type, entry_data, entry_data_sig, entry_met, entry_met_sig])
		
		entry_index += 1 # Increase PFS Entry Index number for user-friendly output and name duplicates
		entry_start = entry_met_sig_end # Next PFS Entry starts after PFS Entry Metadata Signature
	
	# Parse all PFS Information Entries/Descriptors
	info_start = 0 # Increasing PFS Information Entry starting offset
	info_all = [] # Storage for each PFS Information Entry details
	while len(pfs_info[info_start:info_start + pfs_info_size]) == pfs_info_size :
		# Get PFS Information Structure values
		entry_info = get_struct(pfs_info, info_start, PFS_INFO)
		
		# Validate that a known PFS Information Header Version was encountered
		if entry_info.HeaderVersion != 1 :
			print('\n    Error: Unknown PFS Information Header Version %d!' % entry_info.HeaderVersion)
			break # Skip PFS Information Entries/Descriptors in case of assertion error
		
		# Get PFS Information GUID in Big Endian format to match each Info to the equivalent stored PFS Entry details
		entry_guid = ''.join('%0.8X' % int.from_bytes(struct.pack('<I', val), 'little') for val in reversed(entry_info.GUID))
		
		# The PFS Information Structure is not complete by itself. The size of the last field (Entry Name) is determined from CharacterCount
		# multiplied by 2 due to usage of UTF-16 2-byte Characters. Any Entry Name leading and/or trailing space/null characters are stripped
		entry_name = pfs_info[info_start + pfs_info_size:info_start + pfs_info_size + entry_info.CharacterCount * 2].decode('utf-16').strip()
		
		# Get PFS Information Version string via "Version" and "VersionType" fields
		# PFS Information Version string must be preferred over PFS Entry's Version
		entry_version = get_version(entry_info.Version, entry_info.VersionType)
		
		# Store all relevant PFS Information details
		info_all.append([entry_guid, entry_name, entry_version])
		
		# The next PFS Information starts after the calculated Entry Name size
		# Two space/null characters seem to always exist after the Entry Name
		info_start += (pfs_info_size + entry_info.CharacterCount * 2 + 0x2)
		
	# Parse Nested PFS Metadata when its PFS Information Entry is missing
	for index in range(len(entries_all)) :
		if entries_all[index][3] == 'NESTED_PFS' and not pfs_info :
			entry_guid = entries_all[index][1] # Nested PFS Entry GUID in Big Endian format
			entry_metadata = entries_all[index][6] # Use Metadata as PFS Information Entry
			
			# When PFS Information Entry exists, Nested PFS Metadata contains only Model IDs
			# When it's missing, the Metadata structure is large and contains equivalent info
			if len(entry_metadata) >= met_info_size :
				# Get Nested PFS Metadata Structure values
				entry_info = get_struct(entry_metadata, 0, METADATA_INFO)
				
				# As Nested PFS Entry Name, we'll use the actual PFS File Name
				entry_name = entry_info.FileName.decode('utf-8').strip('.exe')
				
				# As Nested PFS Entry Version, we'll use the actual PFS File Version
				entry_version = entry_info.FileVersion.decode('utf-8')
				
				# Store all relevant Nested PFS Metadata/Information details
				info_all.append([entry_guid, entry_name, entry_version])
				
				# Re-set Nested PFS Entry Version from Metadata
				entries_all[index][2] = entry_version
		
	# Parse each PFS Entry Data for special types (zlib or Chunks)
	for index in range(len(entries_all)) :
		entry_data = entries_all[index][4] # Get PFS Entry Data
		entry_type = entries_all[index][3] # Get PFS Entry Type
		
		# Very small PFS Entry Data cannot be of special type
		if len(entry_data) < pfs_header_size : continue
		
		# Get possible PFS Header Structure values
		entry_hdr = get_struct(entry_data, 0, PFS_HDR)
		
		# Check for possibly zlib-compressed (0x4 Compressed Size + Compressed Data) PFS Entry Data
		# The 0xE sized zlib "BIOS" section pattern (0xAA type) should be found after the Compressed Size
		zlib_bios_match = zlib_bios_pattern.search(entry_data)
		
		# Check if a sub PFS Header with Payload has Chunked Entries
		# Chunked Entries can be determined via the "DellX" string
		pfs_entry_struct, pfs_entry_size = get_pfs_entry(entry_data, pfs_header_size)
		chunk_tag_off = pfs_header_size + pfs_entry_size + 0x4 # Chunk Tag starts at 0x4 and is probably 0x10 sized
		chunk_tag = entry_data[chunk_tag_off:chunk_tag_off + 0x10].replace(b'\x00',b'\x20').decode('utf-8','ignore').strip()
		
		if chunk_tag in ('DellX7','DellX11') :
			is_chunk = True
		elif chunk_tag.startswith('Dell') :
			is_chunk = True
			print('\n    Error: Unknown sub PFS Entry Chunk Tag %s!' % chunk_tag)
		else :
			is_chunk = False
		
		if entry_hdr.Tag == b'PFS.HDR.' and is_chunk :
			# Validate that a known sub PFS Header Version was encountered
			if entry_hdr.HeaderVersion not in (1,2) :
				print('\n    Error: Unknown sub PFS Entry Header Version %d!' % entry_hdr.HeaderVersion)
			
			# Get sub PFS Footer Data after sub PFS Header Payload
			chunks_footer = entry_data[pfs_header_size + entry_hdr.PayloadSize:pfs_header_size + entry_hdr.PayloadSize + pfs_footer_size]
			
			# Get sub PFS Footer Structure values
			entry_ftr = get_struct(chunks_footer, 0, PFS_FTR)
			
			# Validate that a sub PFS Footer was parsed
			if entry_ftr.Tag != b'PFS.FTR.' :
				print('\n    Error: Sub PFS Entry Footer could not be found!')
				
			# Validate that the sub PFS Header Payload Size matches the one at the sub PFS Footer
			if entry_hdr.PayloadSize != entry_ftr.PayloadSize :
				print('\n    Error: Sub PFS Entry Header & Footer Payload Size mismatch!')
			
			# Get sub PFS Payload Data
			chunks_payload = entry_data[pfs_header_size:pfs_header_size + entry_hdr.PayloadSize]
			
			# Calculate the sub PFS Payload Data CRC-32 w/ Vector 0 Checksum
			chunks_footer_checksum = ~zlib.crc32(chunks_payload, 0) & 0xFFFFFFFF
			
			# Validate sub PFS Payload Data Checksum via the sub PFS Footer
			if entry_ftr.Checksum != chunks_footer_checksum :
				print('\n    Error: Invalid sub PFS Entry Footer Payload Checksum!')
			
			# Parse all sub PFS Payload Entries/Chunks
			chunk_data_all = [] # Storage for each sub PFS Entry/Chunk Order + Data
			chunk_entry_start = 0 # Increasing sub PFS Entry/Chunk starting offset
			pfs_entry_struct, pfs_entry_size = get_pfs_entry(chunks_payload, chunk_entry_start) # Get PFS_HDR Info
			while len(chunks_payload[chunk_entry_start:chunk_entry_start + pfs_entry_size]) == pfs_entry_size :
				# Get sub PFS Entry Structure values
				pfs_chunk_entry = get_struct(chunks_payload, chunk_entry_start, pfs_entry_struct)
				
				# Validate that a known sub PFS Entry Header Version was encountered
				if pfs_chunk_entry.HeaderVersion not in (1,2) :
					print('\n    Error: Unknown sub PFS Chunk Entry Header Version %d!' % pfs_chunk_entry.HeaderVersion)
				
				# Validate that the sub PFS Entry Reserved field is empty
				if pfs_chunk_entry.Reserved != 0 :
					print('\n    Error: Detected non-empty sub PFS Chunk Entry Reserved field!')
				
				# Get sub PFS Entry Version string via "Version" and "VersionType" fields
				# This is not useful as the Version of each Chunk does not matter at all
				chunk_entry_version = get_version(pfs_chunk_entry.Version, pfs_chunk_entry.VersionType)
				
				# Each sub PFS Payload Entry/Chunk includes some Extra Chunk Data/Information at the beginning
				# We must determine the Chunk Extra Info size to remove its Data from the final Chunk Raw Data
				# The Chunk Extra Info consists of a Header 0x28 (?), variable sized Flags & End of Flags (0x8)
				chunk_raw_size_off = chunk_entry_start + pfs_entry_size + 0x20 # Chunk Raw Data Size is at 0x20-0x24
				chunk_raw_size = int.from_bytes(chunks_payload[chunk_raw_size_off:chunk_raw_size_off + 0x4], 'little')
				chunk_info_size = pfs_chunk_entry.DataSize - chunk_raw_size # Get Chunk Extra Info size
				
				# The sub PFS Payload Entries/Chunks are not in proper order by default
				# However, we can get the Chunk Order Number from a Chunk Extra Info byte
				chunk_entry_number = chunks_payload[chunk_entry_start + pfs_entry_size + 0x3E] # Chunk Order Number is at 0x3E
				
				# Sub PFS Entry Data starts after the sub PFS Entry Structure
				chunk_entry_data_start = chunk_entry_start + pfs_entry_size
				chunk_entry_data_end = chunk_entry_data_start + pfs_chunk_entry.DataSize
				
				# Sub PFS Entry Data Signature starts after sub PFS Entry Data
				chunk_entry_data_sig_start = chunk_entry_data_end
				chunk_entry_data_sig_end = chunk_entry_data_sig_start + pfs_chunk_entry.DataSigSize
				
				# Sub PFS Entry Metadata starts after sub PFS Entry Data Signature
				chunk_entry_met_start = chunk_entry_data_sig_end 
				chunk_entry_met_end = chunk_entry_met_start + pfs_chunk_entry.DataMetSize
				
				# Sub PFS Entry Metadata Signature starts after sub PFS Entry Metadata
				chunk_entry_met_sig_start = chunk_entry_met_end
				chunk_entry_met_sig_end = chunk_entry_met_sig_start + pfs_chunk_entry.DataMetSigSize
				
				chunk_entry_data = chunks_payload[chunk_entry_data_start:chunk_entry_data_end] # Store sub PFS Entry Data
				chunk_entry_data_sig = chunks_payload[chunk_entry_data_sig_start:chunk_entry_data_sig_end] # Store sub PFS Entry Data Signature
				chunk_entry_met = chunks_payload[chunk_entry_met_start:chunk_entry_met_end] # Store sub PFS Entry Metadata
				chunk_entry_met_sig = chunks_payload[chunk_entry_met_sig_start:chunk_entry_met_sig_end] # Store sub PFS Entry Metadata Signature
				
				# Store each sub PFS Entry/Chunk Extra Info Size, Order Number & Raw Data
				chunk_data_all.append((chunk_entry_number, chunk_entry_data, chunk_info_size))
				
				chunk_entry_start = chunk_entry_met_sig_end # Next sub PFS Entry/Chunk starts after sub PFS Entry Metadata Signature
				
				pfs_entry_struct, pfs_entry_size = get_pfs_entry(chunks_payload, chunk_entry_start) # Get Next PFS_HDR Info
				
			chunk_data_all.sort() # Sort all sub PFS Entries/Chunks based on their Order Number
			
			entry_data = b'' # Initialize new PFS Entry Data
			for chunk in chunk_data_all :
				# Merge all sub PFS Chunks into the final new PFS Entry Data
				entry_data += chunk[1][chunk[2]:] # Skip the sub PFS Chunk Extra Info when merging
				
			entry_type = 'CHUNKS' # Re-set PFS Entry Type from OTHER to CHUNKS, in case such info is needed afterwards
		
		# Check if the PFS Entry Data are zlib-compressed in a BIOS pattern (0xAA type). A zlib-compressed
		# PFS Entry Data contains a full PFS structure, like the original Dell PFS BIOS executable
		elif zlib_bios_match :
			compressed_size = int.from_bytes(entry_data[zlib_bios_match.start() - 0x4:zlib_bios_match.start()], 'little')
			entry_data = zlib.decompress(entry_data[zlib_bios_match.start() + 0xC:zlib_bios_match.start() + 0xC + compressed_size])
			
			entry_type = 'ZLIB' # Re-set PFS Entry Type from OTHER to ZLIB, in case such info is needed afterwards
			
			pfs_count += 1 # Increase the count/index of parsed main PFS structures by one
			
			# Get the Name of the zlib-compressed full PFS structure via the already stored PFS Information
			# The zlib-compressed full PFS structure(s) are used to contain multiple BIOS (CombineBiosNameX)
			# When zlib-compressed full PFS structure(s) exist within the main/first full PFS structure,
			# its PFS Information should contain their names (CombineBiosNameX). Since the main/first
			# full PFS structure has count/index 1, the rest start at 2+ and thus, their PFS Information
			# names can be retrieved in order by subtracting 2 from the main/first PFS Information values
			sub_pfs_name = ' %s v%s' % (info_all[pfs_count - 2][1], info_all[pfs_count - 2][2]) if info_all else ' UNKNOWN'
			
			# Recursively call the Dell PFS.HDR. Extractor function for each zlib-compressed full PFS structure
			pfs_extract(entry_data, pfs_count, sub_pfs_name, pfs_count) # For recursive calls, pfs_index = pfs_count
			
		entries_all[index][4] = entry_data # Adjust PFS Entry Data after merging Chunks or zlib-decompressing
		entries_all[index][3] = entry_type # Adjust PFS Entry Type from OTHER to either CHUNKS or ZLIB
		
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
		elif file_type == 'PFS_INFO' :
			file_name = 'PFS Information'
			if not is_advanced : continue # Don't store PFS Information in non-advanced user mode
		else :
			file_name = ''
		
		# Most PFS Entry Names & Versions are found at PFS Information via their GUID
		# Version can be found at PFS_ENTRY but prefer PFS Information when possible
		for info_index in range(len(info_all)) :
			info_guid = info_all[info_index][0]
			info_name = info_all[info_index][1]
			info_version = info_all[info_index][2]
			
			# Give proper Name & Version info if Entry/Information GUIDs match
			if info_guid == file_guid :
				file_name = info_name
				file_version = info_version
				
				info_all[info_index][0] = 'USED' # PFS with zlib-compressed full PFS (multiple BIOS) use the same GUID
				break # Break at 1st Name match to not rename from next zlib-compressed full PFS with the same GUID
		
		data_ext = '.data.bin' if is_advanced else '.bin' # Simpler Data Extension for non-advanced users
		meta_ext = '.meta.bin' if is_advanced else '.bin' # Simpler Metadata Extension for non-advanced users
		full_name = '%d%s -- %d %s v%s' % (pfs_index, pfs_name, file_index, file_name, file_version)
		
		is_zlib = True if file_type == 'ZLIB' else False # Determine if PFS Entry Data was zlib-compressed
		
		# For both advanced & non-advanced users, the goal is to store final/usable files only
		# so empty or intermediate files such as sub-PFS, PFS w/ Chunks or zlib-PFS are skipped
		if file_data and not is_zlib : # Store Data (advanced & non-advanced users)
			# Some Data may be Text or XML files with useful information for non-advanced users
			is_text, final_data, file_ext, write_mode = bin_is_text(file_data, file_type, False, is_advanced)
			
			final_name = '%s%s' % (full_name, data_ext[:-4] + file_ext if is_text else data_ext)
			final_path = os.path.join(output_path, final_name)
			
			with open(final_path, write_mode) as o : o.write(final_data) # Write final Data
		
		if file_data_sig and is_advanced : # Store Data Signature (advanced users only)
			final_name = '%s.data.sig' % full_name
			final_path = os.path.join(output_path, final_name)
			
			with open(final_path, 'wb') as o : o.write(file_data_sig) # Write final Data Signature
		
		# Main/First PFS CombineBiosNameX Metadata files must be kept for accurate Model Information
		# All users should check these files in order to choose the correct CombineBiosNameX modules
		if file_meta and (is_zlib or is_advanced) : # Store Metadata (advanced & maybe non-advanced users)
			# Some Data may be Text or XML files with useful information for non-advanced users
			is_text, final_data, file_ext, write_mode = bin_is_text(file_meta, file_type, True, is_advanced)
			
			final_name = '%s%s' % (full_name, meta_ext[:-4] + file_ext if is_text else meta_ext)
			final_path = os.path.join(output_path, final_name)
			
			with open(final_path, write_mode) as o : o.write(final_data) # Write final Data Metadata
		
		if file_meta_sig and is_advanced : # Store Metadata Signature (advanced users only)
			final_name = '%s.meta.sig' % full_name
			final_path = os.path.join(output_path, final_name)
			
			with open(final_path, 'wb') as o : o.write(file_meta_sig) # Write final Data Metadata Signature
			
# Check if file is Text/XML and Convert
def bin_is_text(buffer, file_type, is_metadata, is_advanced) :
	is_text = False
	write_mode = 'wb'
	extension = '.bin'
	
	# Only for non-advanced users due to signature (.sig) invalidation
	if not is_advanced :
		if b',END' in buffer[-0x6:-0x1] : # Text Type 1
			is_text = True
			write_mode = 'w'
			extension = '.txt'
			buffer = buffer.decode('utf-8').split(',END')[0].replace(';','\n')
		elif buffer.startswith(b'VendorName=Dell') : # Text Type 2
			is_text = True
			write_mode = 'w'
			extension = '.txt'
			if buffer.endswith(b'\x00\x00') : buffer = buffer[:-2]
			buffer = buffer.decode('utf-8').replace(';','\n')
		elif b'<Rimm x-schema="' in buffer[:0x50] : # XML Type
			is_text = True
			write_mode = 'w'
			extension = '.xml'
			buffer = buffer.decode('utf-8')
		elif file_type in ('NESTED_PFS','ZLIB') and is_metadata and len(buffer) == met_info_size : # Text Type 3
			is_text = True
			write_mode = 'w'
			extension = '.txt'
			buffer = get_struct(buffer, 0, METADATA_INFO).pfs_write()
	
	return is_text, buffer, extension, write_mode
	
# Determine PFS Entry Version string via "Version" and "VersionType" fields
def get_version(version_fields, version_types) :
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
			print('\n    Error: Unknown PFS Entry Version Type 0x%0.2X!' % version_types[idx])
			
	return version
	
# Get PFS Entry Structure & Size via its Version
def get_pfs_entry(buffer, offset) :
	pfs_entry_ver = int.from_bytes(buffer[offset + 0x10:offset + 0x14], 'little') # PFS Entry Version
	
	if pfs_entry_ver == 1 : return PFS_ENTRY, ctypes.sizeof(PFS_ENTRY)
	elif pfs_entry_ver == 2 : return PFS_ENTRY_R2, ctypes.sizeof(PFS_ENTRY_R2)
	else : return PFS_ENTRY_R2, ctypes.sizeof(PFS_ENTRY_R2)
			
# Process ctypes Structure Classes
def get_struct(buffer, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack optional parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = buffer[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= len(buffer)) or (fit_len < struct_len) :
		print('\n    Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name))
		
		input('\nPress enter to exit')
		
		sys.exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure
	
# Pause after any unexpected Python exception
def show_exception_and_exit(exc_type, exc_value, tb) :
	if exc_type is KeyboardInterrupt :
		print('\n')
	else :
		print('\nError: %s crashed, please report the following:\n' % title)
		traceback.print_exception(exc_type, exc_value, tb)
		input('\nPress enter to exit')
	
	sys.exit(1)

# Set pause-able Python exception hander
sys.excepthook = show_exception_and_exit

# Show script title
print('\n' + title)

# Set console/shell window title
user_os = sys.platform
if user_os == 'win32' : ctypes.windll.kernel32.SetConsoleTitleW(title)
elif user_os.startswith('linux') or user_os == 'darwin' or user_os.find('bsd') != -1 : sys.stdout.write('\x1b]2;' + title + '\x07')

# Set argparse Arguments
parser = argparse.ArgumentParser()
parser.add_argument('executables', type=argparse.FileType('r'), nargs='*')
parser.add_argument('-a', '--advanced', help='extract in advanced user mode', action='store_true')
args = parser.parse_args()

# Get ctypes Structure Sizes
pfs_header_size = ctypes.sizeof(PFS_HDR)
pfs_footer_size = ctypes.sizeof(PFS_FTR)
pfs_info_size = ctypes.sizeof(PFS_INFO)
met_info_size = ctypes.sizeof(METADATA_INFO)

if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	pfs_exec = []
	for executable in args.executables :
		pfs_exec.append(executable.name)
else :
	# Folder path
	pfs_exec = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			pfs_exec.append(os.path.join(root, name))

# Process each input Dell PFS BIOS executable
for input_file in pfs_exec :
	input_name,input_extension = os.path.splitext(os.path.basename(input_file))
	input_dir = os.path.dirname(os.path.abspath(input_file))
	
	print('\nFile: %s%s' % (input_name, input_extension))
	
	# Check if input file exists
	if not os.path.isfile(input_file) :
		print('\n    Error: This input file does not exist!')
		continue # Next input file
	
	with open(input_file, 'rb') as in_file : input_data = in_file.read()
	
	# The Dell PFS BIOS executables may contain more than one section. Each section is zlib-compressed
	# with header pattern ++EEAA761BECBB20F1E651--789C where ++ is the section type and -- a random number
	# The "BIOS" section has type 0xAA and its files are stored in PFS format. The "Utility" section has
	# type 0xBB and its files are stored in PFS, BIN or 7-Zip formats. There could be more section types
	# but for the purposes of this utility, we are only interested in extracting the "BIOS" section files
	zlib_bios_pattern = re.compile(br'\xAA\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78\x9C', re.DOTALL)
	
	zlib_bios_match = zlib_bios_pattern.search(input_data) # Search input executable for zlib "BIOS" section
	
	# Check if zlib-compressed "BIOS" section with type 0xAA was found in the executable
	if not zlib_bios_match :
		print('\n    Error: This is not a Dell PFS BIOS executable!')
		continue # Next input file
	
	# Store the compressed zlib data size from the preceding 4 bytes of the "BIOS" section header pattern
	compressed_size = int.from_bytes(input_data[zlib_bios_match.start() - 0x4:zlib_bios_match.start()], 'little')
	
	# Decompress "BIOS" section payload, starting from zlib header start of 0x789C
	input_data = zlib.decompress(input_data[zlib_bios_match.start() + 0xC:zlib_bios_match.start() + 0xC + compressed_size])
	
	output_path = os.path.join(input_dir, '%s%s' % (input_name, input_extension) + '_extracted') # Set extraction directory
	
	if os.path.isdir(output_path) : shutil.rmtree(output_path) # Delete any existing extraction directory
	
	os.mkdir(output_path) # Create extraction directory
	
	pfs_name = '' # N/A for Main/First/Initial full PFS, used for sub-PFS recursions
	pfs_index = 1 # Main/First/Initial full PFS Index is 1
	pfs_count = 1 # Main/First/Initial full PFS Count is 1
	is_advanced = True if args.advanced else False # Set Advanced user mode optional argument
	
	pfs_extract(input_data, pfs_index, pfs_name, pfs_count) # Call the Dell PFS.HDR. Extractor function
	
	print('\n    Extracted Dell PFS BIOS executable!')

else :
	input('\nDone!')
	
	sys.exit(0)