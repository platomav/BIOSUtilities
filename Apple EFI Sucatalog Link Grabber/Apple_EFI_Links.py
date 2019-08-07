#!/usr/bin/env python3

"""
Apple EFI Links
Apple EFI Sucatalog Link Grabber
Copyright (C) 2018-2019 Plato Mavropoulos
"""

print('Apple EFI Sucatalog Link Grabber v1.2\n')

import os
import sys
import datetime

# Remove previous output files
if os.path.isfile('OUT.txt') : os.remove('OUT.txt')

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

print('Working...')
				
# Parse each input xml file
for input_file in catalogs :
	input_name,input_extension = os.path.splitext(os.path.basename(input_file))
	
	print('\n%s%s' % (input_name, input_extension))
	
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
		
		current_datetime = datetime.datetime.utcnow().isoformat(timespec='seconds').replace('-','').replace('T','').replace(':','')
		
		output_file = 'EFI %s.txt' % current_datetime
		
		with open(output_file, 'w') as efi_file : efi_file.write(final_lines) # Save final output file
		
		print('\nStored %s!' % output_file)
		
	os.remove('OUT.txt') # Remove temporary output file
	
input('\nDone!')