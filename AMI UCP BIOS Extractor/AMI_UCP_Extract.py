#!/usr/bin/env python3
#coding=utf-8

"""
AMI UCP Extract
AMI UCP BIOS Extractor
Copyright (C) 2021 Plato Mavropoulos
"""

title = 'AMI UCP BIOS Extractor v1.0'

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
import shutil
import ctypes
import argparse
import traceback
import subprocess
import contextlib

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
ucp_parser = argparse.ArgumentParser()
ucp_parser.add_argument('executables', type=argparse.FileType('r'), nargs='*')
ucp_parser.add_argument('-p', '--path', help='parse files within given folder', type=str)
ucp_parser.add_argument('-c', '--checksum', help='verify AMI UCP Checksums (slow)', action='store_true')
ucp_params = ucp_parser.parse_args()

verify_chk16 = bool(ucp_params.checksum) # Get Checksum16 Verification optional argument

# Get all files within path
def get_files(path) :
	inputs = []
	
	for root, _, files in os.walk(path):
		for name in files :
			inputs.append(os.path.join(root, name))
	
	return inputs

if len(sys.argv) >= 2 :
	if bool(ucp_params.path) :
		ucp_exec = get_files(ucp_params.path) # CLI with --path
	else :
		ucp_exec = []
		for executable in ucp_params.executables :
			ucp_exec.append(executable.name) # Drag & Drop
else :
	in_path = input('\nEnter the full folder path: ')
	ucp_exec = get_files(in_path) # Direct Run

# Set ctypes Structure types
char = ctypes.c_char
uint8_t = ctypes.c_ubyte
uint16_t = ctypes.c_ushort
uint32_t = ctypes.c_uint
uint64_t = ctypes.c_uint64

class UAF_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('ModuleTag',			char*4),		# 0x00
		('ModuleSize',			uint32_t),		# 0x04
		('Checksum',			uint16_t),		# 0x08
		('Unknown0',			uint8_t),		# 0x0A
		('Unknown1',			uint8_t),		# 0x0A
		('Reserved',			uint32_t),		# 0x0C
		# 0x10
	]
	
	def __init__(self, padd, *args, **kwargs) :
		super().__init__(*args, **kwargs)
		self.p = padd
	
	def ucp_print(self, chk16) :
		print('\n%s    Utility Auxiliary File:\n' % self.p)
		print('%s        Module Tag    : %s' % (self.p, self.ModuleTag.decode('utf-8')))
		print('%s        Module Size   : 0x%X' % (self.p, self.ModuleSize))
		print('%s        Checksum      : 0x%0.4X (%s)' % (self.p, self.Checksum, chk16))
		print('%s        Unknown 0     : 0x%0.2X' % (self.p, self.Unknown0))
		print('%s        Unknown 1     : 0x%0.2X' % (self.p, self.Unknown1))
		print('%s        Reserved      : 0x%0.8X' % (self.p, self.Reserved))

class UAF_MOD(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('CompressSize',		uint32_t),		# 0x00
		('OriginalSize',		uint32_t),		# 0x04
		# 0x08
	]
	
	def __init__(self, padd, *args, **kwargs) :
		super().__init__(*args, **kwargs)
		self.p = padd
	
	def ucp_print(self) :
		print('%s        Compress Size : 0x%X' % (self.p, self.CompressSize))
		print('%s        Original Size : 0x%X' % (self.p, self.OriginalSize))

class UII_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('UIISize',				uint16_t),		# 0x00
		('Checksum',			uint16_t),		# 0x02
		('UtilityVersion',		uint32_t),		# 0x04 i.e. AFU (Unknown Encoding, Signed)
		('InfoSize',			uint16_t),		# 0x08
		('SupportBIOS',			uint8_t),		# 0x0A
		('SupportOS',			uint8_t),		# 0x0B
		('DataBusWidth',		uint8_t),		# 0x0C
		('ProgramType',			uint8_t),		# 0x0D
		('ProgramMode',			uint8_t),		# 0x0E
		('SourceSafeRelease',	uint8_t),		# 0x0F
		# 0x10
	]
	
	def __init__(self, padd, *args, **kwargs) :
		super().__init__(*args, **kwargs)
		self.p = padd
	
	def ucp_print(self, chk16) :
		sbios = {1: 'ALL', 2: 'AMIBIOS8', 3: 'UEFI', 4: 'AMIBIOS8/UEFI'}
		sos = {1: 'DOS', 2: 'EFI', 3: 'Windows', 4: 'Linux', 5: 'FreeBSD', 6: 'MacOS', 128: 'Multi-Platform'}
		dbwidth = {1: '16b', 2: '16/32b', 3: '32b', 4: '64b'}
		ptype = {1: 'Executable', 2: 'Library', 3: 'Driver'}
		pmode = {1: 'API', 2: 'Console', 3: 'GUI', 4: 'Console/GUI'}
		
		SupportBIOS = sbios[self.SupportBIOS] if self.SupportBIOS in sbios else 'Unknown (%d)' % self.SupportBIOS
		SupportOS = sos[self.SupportOS] if self.SupportOS in sos else 'Unknown (%d)' % self.SupportOS
		DataBusWidth = dbwidth[self.DataBusWidth] if self.DataBusWidth in dbwidth else 'Unknown (%d)' % self.DataBusWidth
		ProgramType = ptype[self.ProgramType] if self.ProgramType in ptype else 'Unknown (%d)' % self.ProgramType
		ProgramMode = pmode[self.ProgramMode] if self.ProgramMode in pmode else 'Unknown (%d)' % self.ProgramMode
		
		print('\n%s        Utility Identification Information:\n' % self.p)
		print('%s            UII Size       : 0x%X' % (self.p, self.UIISize))
		print('%s            Checksum       : 0x%0.4X (%s)' % (self.p, self.Checksum, chk16))
		print('%s            Tool Version   : 0x%0.8X (Unknown)' % (self.p, self.UtilityVersion))
		print('%s            Info Size      : 0x%X' % (self.p, self.InfoSize))
		print('%s            Supported BIOS : %s' % (self.p, SupportBIOS))
		print('%s            Supported OS   : %s' % (self.p, SupportOS))
		print('%s            Data Bus Width : %s' % (self.p, DataBusWidth))
		print('%s            Program Type   : %s' % (self.p, ProgramType))
		print('%s            Program Mode   : %s' % (self.p, ProgramMode))
		print('%s            SourceSafe Tag : %0.2d' % (self.p, self.SourceSafeRelease))

class DIS_HDR(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('PasswordSize',		uint16_t),		# 0x00
		('EntryCount',			uint16_t),		# 0x02
		('Password',			char*12),		# 0x04
		# 0x10
	]
	
	def __init__(self, padd, *args, **kwargs) :
		super().__init__(*args, **kwargs)
		self.p = padd
	
	def ucp_print(self) :
		print('\n%s        Default Command Status Header:\n' % self.p)
		print('%s            Password Size : 0x%X' % (self.p, self.PasswordSize))
		print('%s            Entry Count   : %d' % (self.p, self.EntryCount))
		print('%s            Password      : %s' % (self.p, self.Password.decode('utf-8')))

class DIS_MOD(ctypes.LittleEndianStructure) :
	_pack_ = 1
	_fields_ = [
		('EnabledDisabled',		uint8_t),		# 0x00
		('ShownHidden',			uint8_t),		# 0x01
		('Command',				char*32),		# 0x02
		('Description',			char*256),		# 0x22
		# 0x122
	]
	
	def __init__(self, padd, *args, **kwargs) :
		super().__init__(*args, **kwargs)
		self.p = padd
	
	def ucp_print(self) :
		enabled = {0: 'Disabled', 1: 'Enabled'}
		shown = {0: 'Hidden', 1: 'Shown', 2: 'Shown Only'}
		
		EnabledDisabled = enabled[self.EnabledDisabled] if self.EnabledDisabled in enabled else 'Unknown (%d)' % self.EnabledDisabled
		ShownHidden = shown[self.ShownHidden] if self.ShownHidden in shown else 'Unknown (%d)' % self.ShownHidden
		
		print('\n%s        Default Command Status Entry:\n' % self.p)
		print('%s            State       : %s' % (self.p, EnabledDisabled))
		print('%s            Display     : %s' % (self.p, ShownHidden))
		print('%s            Command     : %s' % (self.p, self.Command.decode('utf-8').strip()))
		print('%s            Description : %s' % (self.p, self.Description.decode('utf-8').strip()))

# Process ctypes Structure Classes
# https://github.com/skochinsky/me-tools/blob/master/me_unpack.py by Igor Skochinsky
def get_struct(buffer, start_offset, class_name, param_list = None) :
	if param_list is None : param_list = []
	
	structure = class_name(*param_list) # Unpack parameter list
	struct_len = ctypes.sizeof(structure)
	struct_data = buffer[start_offset:start_offset + struct_len]
	fit_len = min(len(struct_data), struct_len)
	
	if (start_offset >= len(buffer)) or (fit_len < struct_len) :
		print('\n        Error: Offset 0x%X out of bounds at %s, possibly incomplete image!' % (start_offset, class_name.__name__))
		
		input('\n        Press enter to exit')
		
		sys.exit(1)
	
	ctypes.memmove(ctypes.addressof(structure), struct_data, fit_len)
	
	return structure

# Get Checksum16 validity result
def checksum16(buffer, check) :
	if not check : return 'Skipped'
	
	chk16 = 0
	
	for idx in range(0, len(buffer), 2) :
		chk16 += int.from_bytes(buffer[idx:idx + 2], 'little')
	
	chk16 &= 0xFFFF
	
	return 'Good' if chk16 == 0 else 'Bad'

# Get all input file AMI UCP patterns
def get_matches(buffer) :
	uaf_len_max = 0 # Length of largest detected @UAF
	uaf_hdr_off = 0 # Offset of largest detected @UAF
	
	for uaf in ami_ucp_pat.finditer(buffer) :
		uaf_len_cur = int.from_bytes(buffer[uaf.start() + 0x4:uaf.start() + 0x8], 'little')
		
		if uaf_len_cur > uaf_len_max :
			uaf_len_max = uaf_len_cur
			uaf_hdr_off = uaf.start()
	
	return uaf_hdr_off, uaf_len_max

# Parse & Extract AMI UCP structures
def ucp_extract(buffer, out_dir, level, padd) :
	nal_dict = {} # Initialize @NAL Dictionary per UCP
	
	uaf_hdr = get_struct(buffer, 0, UAF_HDR, [padd]) # Parse @UAF Header Structure
	
	uaf_chk = checksum16(buffer, verify_chk16) # Get @UAF Header Checksum16
	
	# Print @UAF Header Info
	uaf_hdr.ucp_print(uaf_chk)
	print('%s        Compress Size : 0x%X' % (padd, len(buffer)))
	print('%s        Original Size : 0x%X' % (padd, len(buffer)))
	print('%s        Module Name   : %s' % (padd, tag_dict['UAF']))
	
	if uaf_chk == 'Bad' :
		input('\n%s        Error: Invalid AMI UCP Module UAF Checksum!' % padd)
	
	uaf_off = uaf_hdr_len # Parsed @UAF, next Modules
	uaf_all = [] # Initialize list of all UAF Modules
	is_pfat = False # Initialize PFAT BIOS detection
	is_dual = False # Initialize AMI/Insyde detection
	
	while buffer[uaf_off] == 0x40 : # ASCII of @ is 0x40
		uaf_hdr = get_struct(buffer, uaf_off, UAF_HDR, [padd]) # Parse UAF Module Structure
		
		uaf_tag = uaf_hdr.ModuleTag.decode('utf-8')[1:] # Get unique UAF Module Tag
		
		if uaf_tag == 'PFC' : is_pfat = True # Detect if UAF Module has PFAT BIOS
		
		if uaf_tag == 'AMI' : is_dual = True # Detect if UAF Module has dual AMI/Insyde BIOS
		
		uaf_all.append([uaf_tag, uaf_off, uaf_hdr]) # Store UAF Module Info
		
		uaf_off += uaf_hdr.ModuleSize # Adjust to next UAF Module offset
		
		if uaf_off >= len(buffer) : break # Stop parsing at EOF
	
	# Check if UAF Module NAL exists and place it first
	# Parsing NAL first allows naming all UAF Modules
	for i in range(len(uaf_all)) :
		if uaf_all[i][0] == 'NAL' :
			uaf_all.insert(1, uaf_all.pop(i)) # After UII for visual purposes
			break # NAL found, skip the rest
	
	# Parse all UAF Modules
	for uaf in uaf_all :
		uaf_tag = uaf[0] # Store UAF Module Tag
		uaf_off = uaf[1] # Store UAF Module Offset
		uaf_hdr = uaf[2] # Store UAF Module Struct
		
		uaf_data_all = buffer[uaf_off:uaf_off + uaf_hdr.ModuleSize] # UAF Module Entire Data
		
		uaf_data_mod = uaf_data_all[uaf_hdr_len:] # UAF Module EFI Data
		
		uaf_data_raw = uaf_data_mod[uaf_mod_len:] # UAF Module Raw Data
		
		uaf_chk = checksum16(uaf_data_all, verify_chk16) # Get UAF Module Checksum16
		
		uaf_hdr.ucp_print(uaf_chk) # Print UAF Module Info
		
		uaf_mod = get_struct(buffer, uaf_off + uaf_hdr_len, UAF_MOD, [padd]) # Parse UAF Module EFI Structure
		
		uaf_mod.ucp_print() # Print UAF Module EFI Info
		
		is_comp = uaf_mod.CompressSize != uaf_mod.OriginalSize # Detect UAF Module EFI Compression
		
		rom_name = 'PFAT' if is_pfat else 'BIOS' # Set UAF Module BIOS/ROM name based on PFAT state
		
		if uaf_tag in nal_dict : uaf_name = nal_dict[uaf_tag] # Always prefer NAL naming first
		elif uaf_tag in tag_dict : uaf_name = tag_dict[uaf_tag] # Otherwise use built-in naming
		elif uaf_tag == 'ROM' : uaf_name = '%s.bin' % rom_name # BIOS/PFAT Firmware
		elif uaf_tag.startswith('R0') : uaf_name = '%s_0%s.bin' % (rom_name, uaf_tag[2:]) # BIOS/PFAT Firmware
		elif uaf_tag.startswith('S0') : uaf_name = '%s_0%s.sig' % (rom_name, uaf_tag[2:]) # BIOS/PFAT Signature
		elif uaf_tag.startswith('DR') : uaf_name = 'DROM_0%s.bin' % uaf_tag[2:] # Thunderbolt Retimer Firmware
		elif uaf_tag.startswith('DS') : uaf_name = 'DROM_0%s.sig' % uaf_tag[2:] # Thunderbolt Retimer Signature
		elif uaf_tag.startswith('EC') : uaf_name = 'EC_0%s.bin' % uaf_tag[2:] # Embedded Controller Firmware
		elif uaf_tag.startswith('ME') : uaf_name = 'ME_0%s.bin' % uaf_tag[2:] # Management Engine Firmware
		else : uaf_name = uaf_tag # Could not name the UAF Module, use Tag instead
		
		if uaf_name != uaf_tag :
			uaf_fext = '' # File extension included in name
			print('%s        Module Name   : %s' % (padd, uaf_name))
		elif uaf_tag in ['CMD','PFC','VER','MEC','NAL','CKV'] :
			uaf_fext = '.txt' # Known Text files
			print('%s        Module Name   : %s%s (Unknown)' % (padd, uaf_name, uaf_fext))
		else :
			uaf_fext = '.bin' # Unknown files, assume binary
			print('%s        Module Name   : %s%s (Unknown)' % (padd, uaf_name, uaf_fext))
		
		# Check if unknown UAF Module Tag is present in NAL but not in built-in dictionary
		if uaf_tag in nal_dict and uaf_tag not in tag_dict and not uaf_tag.startswith(('ROM','R0','S0','DR','DS')) :
			input('\n%s        Note: Detected new AMI UCP Module %s (%s) in NAL!' % (padd, uaf_tag, nal_dict[uaf_tag]))
		
		# Generate UAF Module File name, depending on whether decompression will be required
		uaf_fname = os.path.join(out_dir, '%s%s' % (uaf_name, '.temp' if is_comp else uaf_fext))
		
		if uaf_chk == 'Bad' :
			input('\n%s        Error: Invalid AMI UCP Module %s Checksum!' % (padd, uaf_tag))
		
		# Parse Utility Identification Information UAF Module (UII)
		if uaf_tag == 'UII' :
			info_hdr = get_struct(uaf_data_raw, 0, UII_HDR, [padd]) # Parse UII Module Raw Structure
			
			info_chk = checksum16(uaf_data_raw, verify_chk16) # Get UII Module Checksum16
			
			info_hdr.ucp_print(info_chk) # Print UII Module Info
			
			# Get UII Module Description text field
			desc = uaf_data_raw[info_hdr.InfoSize:info_hdr.UIISize].strip(b'\x00').decode('utf-8')
			
			print('%s            Description    : %s' % (padd, desc)) # Print UII Module Description
			
			if info_chk == 'Bad' :
				input('\n%s            Error: Invalid AMI UCP Module %s > Info Checksum!' % (padd, uaf_tag))
			
			# Store/Save UII Module Info in file
			with open(uaf_fname[:-3] + 'txt', 'a') as uii :
				with contextlib.redirect_stdout(uii) :
					info_hdr.ucp_print(info_chk) # Store UII Module Info
					
					print('%s            Description    : %s' % (padd, desc)) # Store UII Module Description
		
		# Process and Print known text only UAF Modules
		if uaf_tag in ['CMD','PFC','VER','MEC','CKV'] : # Always referenced in tag_desc
			text_data = uaf_data_raw.decode('utf-8')
			print('\n%s        %s:\n\n%s            %s' % (padd, tag_desc[uaf_tag], padd, text_data))
		
		# Adjust UAF Module Raw Data for extraction
		if is_comp :
			# Some Compressed UAF Module EFI data lack necessary padding in the end
			if uaf_mod.CompressSize > len(uaf_data_raw) :
				comp_padd = b'\x00' * (uaf_mod.CompressSize - len(uaf_data_raw))
				uaf_data_raw = uaf_data_mod[:uaf_mod_len] + uaf_data_raw + comp_padd # Add missing padding for decompression
			else :
				uaf_data_raw = uaf_data_mod[:uaf_mod_len] + uaf_data_raw # Add the EFI/Tiano Compression info before Raw Data
		else :
			uaf_data_raw = uaf_data_raw[:uaf_mod.OriginalSize] # No compression, extend to end of Original UAF Module size
		
		# Store/Save UAF Module file
		if uaf_tag != 'UII' : # Skip UII binary, already parsed
			with open(uaf_fname, 'wb') as out : out.write(uaf_data_raw)
		
		# UAF Module EFI/Tiano Decompression
		if is_comp :
			try :
				dec_fname = uaf_fname[:-5] + uaf_fext # Decompressed UAF Module file path
				subprocess.run(['TianoCompress', '-d', uaf_fname, '-o', dec_fname, '--uefi', '-q'], check = True, stdout = subprocess.DEVNULL)
				
				with open(dec_fname, 'rb') as dec : uaf_data_raw = dec.read() # Read back the UAF Module decompressed Raw data
				
				if len(uaf_data_raw) == 0 : raise Exception('DECOMP_OUT_EMPTY') # If decompressed file is empty, something went wrong
				
				os.remove(uaf_fname) # Successful decompression, delete compressed UAF Module file
				
				uaf_fname = dec_fname # Adjust UAF Module file path to the decompressed one
			except :
				print('\n%s        Error: Could not extract AMI UCP Module %s via TianoCompress!' % (padd, uaf_tag))
				input('%s               Make sure that "TianoCompress" executable exists!' % padd)
		
		# Parse Default Command Status UAF Module (DIS)
		if len(uaf_data_raw) and uaf_tag == 'DIS' :
			dis_hdr = get_struct(uaf_data_raw, 0, DIS_HDR, [padd]) # Parse DIS Module Raw Header Structure
			dis_hdr.ucp_print() # Print DIS Module Raw Header Info
			
			# Store/Save DIS Module Header Info in file
			with open(uaf_fname[:-3] + 'txt', 'a') as dis :
				with contextlib.redirect_stdout(dis) :
					dis_hdr.ucp_print() # Store DIS Module Header Info
			
			dis_data = uaf_data_raw[uaf_hdr_len:] # DIS Module Entries Data
			
			# Parse all DIS Module Entries
			for e_idx in range(dis_hdr.EntryCount) :
				dis_mod = get_struct(dis_data, e_idx * 0x122, DIS_MOD, [padd]) # Parse DIS Module Raw Entry Structure
				dis_mod.ucp_print() # Print DIS Module Raw Entry Info
				
				# Store/Save DIS Module Entry Info in file
				with open(uaf_fname[:-3] + 'txt', 'a') as dis :
					with contextlib.redirect_stdout(dis) :
						dis_mod.ucp_print() # Store DIS Module Entry Info
			
			os.remove(uaf_fname) # Delete DIS Module binary, info exported as text
		
		# Parse Non-AMI List (?) UAF Module (NAL)
		if len(uaf_data_raw) >= 5 and (uaf_tag,uaf_data_raw[0],uaf_data_raw[4]) == ('NAL',0x40,0x3A) :
			nal_info = uaf_data_raw.decode('utf-8').strip().replace('\r','').split('\n')
			
			print('\n%s        UAF List:\n' % padd)
			
			# Parse all NAL Module Entries
			for info in nal_info :
				print('%s            %s : %s' % (padd, info[1:4], info[5:])) # Print NAL Module Tag-Path Info
				nal_dict[info[1:4]] = os.path.basename(info[5:]) # Assign a file name (w/o path) to each Tag
		
		# Parse Insyde BIOS UAF Module (INS)
		if len(uaf_data_raw) >= 2 and (uaf_tag,is_dual,uaf_data_raw[:2]) == ('INS',True,b'\x4D\x5A') :
			ins_dir = os.path.join(out_dir, '%s_extracted (SFX)' % uaf_tag) # Generate extraction directory
			
			print('\n%s        Insyde BIOS 7-Zip SFX Archive:\n\n%s            7-Zip will be used for extraction' % (padd, padd))
			
			# INS Module extraction
			try :
				subprocess.run(['7z', 'x', '-aou', '-bso0', '-bse0', '-bsp0', '-o' + ins_dir, uaf_fname], check = True, stdout = subprocess.DEVNULL)
				
				if not os.path.isdir(ins_dir) : raise Exception('EXTR_DIR_MISSING') # If extraction folder is missing, something went wrong
				
				os.remove(uaf_fname) # Successful extraction, delete archived INS Module file
			except :
				print('\n%s        Error: Could not extract AMI UCP Module %s via 7-Zip!' % (padd, uaf_tag))
				input('%s               Make sure that "7z" executable exists!' % padd)
		
		# Detect AMI BIOS Guard (PFAT) image and print extraction instructions/utility
		if len(uaf_data_raw) >= 16 and (is_pfat,uaf_data_raw[0x8:0x10]) == (True,b'_AMIPFAT') :
			print('\n%s        AMI BIOS Guard (PFAT) Image:\n' % padd)
			print('%s            Use "AMI BIOS Guard Extractor" from https://github.com/platomav/BIOSUtilities' % padd)
		
		# Detect Intel Management Engine (ME) image and print parsing instructions/utility
		if len(uaf_data_raw) and uaf_tag.startswith('ME') :
			print('\n%s        Intel Management Engine (ME) Image:\n' % padd)
			print('%s            Use "ME Analyzer" from https://github.com/platomav/MEAnalyzer' % padd)
		
		# Get best Nested AMI UCP Pattern match based on @UAF Size
		uaf_hdr_off,uaf_len_max = get_matches(uaf_data_raw)
		
		# Parse Nested AMI UCP Structure
		if uaf_hdr_off :
			level += 1 # Increase structure Level to control output padding
			uaf_dir = os.path.join(out_dir, '%s_extracted (UCP)' % uaf_tag) # Generate extraction directory
			os.mkdir(uaf_dir) # Create extraction directory
			ucp_extract(uaf_data_raw[uaf_hdr_off:uaf_hdr_off + uaf_len_max], uaf_dir, level, '    ' * level) # Call recursively
			os.remove(uaf_fname) # Delete raw nested AMI UCP Structure after successful recursion/extraction

# Utility Auxiliary File (@UAF) and Utility Identification Information (@UII)
ami_ucp_pat = re.compile(br'\x40\x55\x41\x46.{12}\x40\x55\x49\x49', re.DOTALL)

# Get common ctypes Structure Sizes
uaf_hdr_len = ctypes.sizeof(UAF_HDR)
uaf_mod_len = ctypes.sizeof(UAF_MOD)

# User friendly Tag Descriptions
tag_desc = {
			'CMD' : 'AMI AFU Command',
			'PFC' : 'AMI BGT Command',
			'VER' : 'OEM Version',
			'CKV' : 'Check Version',
			'MEC' : 'ME FWUpdLcl',
			}

# AMI UCP Tag-File Dictionary
tag_dict = {
			'W32' : 'amifldrv32.sys',
			'W64' : 'amifldrv64.sys',
			'VXD' : 'amifldrv.vxd',
			'DCT' : 'DevCon32.exe',
			'DCX' : 'DevCon64.exe',
			'CMD' : 'AFU_Command.txt',
			'PFC' : 'BGT_Command.txt',
			'VER' : 'OEM_Version.txt',
			'CKV' : 'Check_Version.txt',
			'DIS' : 'Command_Status.bin',
			'UAF' : 'UCP_Main.bin',
			'UII' : 'UCP_Info.txt',
			'NAL' : 'UAF_List.txt',
			'MEC' : 'FWUpdLcl.txt',
			'MED' : 'FWUpdLcl_DOS.exe',
			'MET' : 'FWUpdLcl_WIN.exe',
			'AMI' : 'UCP_Nested.bin',
			'INS' : 'Insyde_Nested.bin',
			'RFI' : 'CryptRSA.efi',
			'R3I' : 'CryptRSA32.efi',
			'UFI' : 'HpBiosUpdate.efi',
			'US9' : 'HpBiosUpdate.s09',
			'US2' : 'HpBiosUpdate.s12',
			'USG' : 'HpBiosUpdate.sig',
			'3FI' : 'HpBiosUpdate32.efi',
			'3S9' : 'HpBiosUpdate32.s09',
			'3S2' : 'HpBiosUpdate32.s12',
			'3SG' : 'HpBiosUpdate32.sig',
			'MFI' : 'HpBiosMgmt.efi',
			'MS9' : 'HpBiosMgmt.s09',
			'MS2' : 'HpBiosMgmt.s12',
			'US4' : 'HpBiosUpdate.s14',
			'3S4' : 'HpBiosUpdate32.s14',
			'MS4' : 'HpBiosMgmt.s14',
			'M3I' : 'HpBiosMgmt32.efi',
			'M39' : 'HpBiosMgmt32.s09',
			'M32' : 'HpBiosMgmt32.s12',
			'M34' : 'HpBiosMgmt32.s14',
			'BME' : 'BiosMgmt.efi',
			'BM9' : 'BiosMgmt.s09',
			'B12' : 'BiosMgmt.s12',
			'B14' : 'BiosMgmt.s14',
			'B3E' : 'BiosMgmt32.efi',
			'B39' : 'BiosMgmt32.s09',
			'B32' : 'BiosMgmt32.s12',
			'B34' : 'BiosMgmt32.s14',
			'DFE' : 'HpDevFwUpdate.efi',
			'DFS' : 'HpDevFwUpdate.s12',
			}

# Process each input AMI UCP BIOS executable
for input_file in ucp_exec :
	input_name,input_extension = os.path.splitext(os.path.basename(input_file))
	input_dir = os.path.dirname(os.path.abspath(input_file))
	
	print('\n*** %s%s' % (input_name, input_extension))
	
	# Check if input file exists
	if not os.path.isfile(input_file) :
		print('\n    Error: This input file does not exist!')
		continue # Next input file
	
	with open(input_file, 'rb') as in_file : input_data = in_file.read()
	
	# Get best AMI UCP Pattern match based on @UAF Size
	uaf_hdr_off,uaf_len_max = get_matches(input_data)
	
	# Check if AMI UCP Pattern was found on executable
	if not uaf_hdr_off :
		print('\n    Error: This is not an AMI UCP BIOS executable!')
		continue # Next input file
	
	output_path = os.path.join(input_dir, '%s%s' % (input_name, input_extension) + '_extracted') # Set extraction directory
	
	if os.path.isdir(output_path) : shutil.rmtree(output_path) # Delete any existing extraction directory
	
	os.mkdir(output_path) # Create extraction directory
	
	print('\n    AMI Utility Configuration Program')
	
	level = 0 # Set initial AMI UCP structure Level to control padding in nested ones
	
	ucp_extract(input_data[uaf_hdr_off:uaf_hdr_off + uaf_len_max], output_path, level, '') # Call the AMI UCP Extractor function
	
	print('\n    Extracted AMI UCP BIOS executable!')

input('\nDone!')

sys.exit(0)