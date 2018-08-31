#!/usr/bin/env python3

"""
Apple EFI Links
Apple EFI Sucatalog Link Grabber
Copyright (C) 2018 Plato Mavropoulos
"""

print('Apple EFI Sucatalog Link Grabber v1.0\n')

import os
import sys

# Remove previous output files
if os.path.isfile('OUT.txt') : os.remove('OUT.txt')
if os.path.isfile('EFI.txt') : os.remove('EFI.txt')

# Get input catalog file paths
if len(sys.argv) >= 2 :
	# Drag & Drop or CLI
	catalogs = sys.argv[1:]
else :
	# Working directory
	catalogs = []
	for root, dirs, files in os.walk(os.getcwd()) :
		for name in files :
			if name.endswith('.sucatalog') :
				catalogs.append(os.path.join(root, name))

# Parse each input xml file
for input_file in catalogs :
	with open(input_file, 'r') as in_file :
		for line in in_file :
			# Find EFI Firmware package links
			if ('.pkg' in line or '.tar' in line) and ('FirmwareUpd' in line or '/BridgeOSUpdateCustomer' in line or 'EFIUpd' in line) \
			and 'Bluetooth' not in line and 'DPVGA' not in line and 'Thunderbolt' not in line and 'PMG5' not in line and 'HardDrive' not in line :
				if '.pkg' in line : link = line[line.find('http'):line.find('.pkg') + 4] # Remove xml formatting
				else : link = line[line.find('http'):line.find('.tar') + 4]
				
				with open('OUT.txt', 'a') as out_file : out_file.write(link + '\n') # Store links in temporary output file

# Parse temporary output file			
if os.path.isfile('OUT.txt') :
	with open('OUT.txt', 'r+') as out_file :
		parsed_lines = []
		final_lines = []
		
		for line in out_file :
			if line not in parsed_lines : # Remove duplicate links
				final_lines.append(line)
				parsed_lines.append(line)
		
		final_lines = ''.join(map(str, sorted(final_lines)))
		
		with open('EFI.txt', 'w') as efi_file : efi_file.write(final_lines) # Save final output file
		
	os.remove('OUT.txt') # Remove temporary output file
	
input('Done!')