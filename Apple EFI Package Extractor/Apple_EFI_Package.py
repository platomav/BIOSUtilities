#!/usr/bin/env python3

"""
Apple EFI Package
Apple EFI Package Extractor
Copyright (C) 2019 Plato Mavropoulos
"""

print('Apple EFI Package Extractor v1.1')

import os
import sys
import zlib
import shutil
import subprocess

if len(sys.argv) >= 2 :
	pkg = sys.argv[1:]
else :
	pkg = []
	in_path = input('\nEnter the full folder path: ')
	print('\nWorking...')
	for root, dirs, files in os.walk(in_path):
		for name in files :
			pkg.append(os.path.join(root, name))

anytoiso_path = 'C:\\Program Files (x86)\\AnyToISO\\anytoiso.exe'
			
final_path = os.path.join(os.getcwd(), 'AppleEFI')
if os.path.exists(final_path) : shutil.rmtree(final_path)
			
for input_file in pkg :
	file_path = os.path.abspath(input_file)
	file_name = os.path.basename(input_file)
	file_dir = os.path.dirname(file_path)
	file_ext = os.path.splitext(file_path)[1]
	
	print('\nFile: %s\n' % file_name)
	
	with open(input_file, 'rb') as in_buff : file_adler = zlib.adler32(in_buff.read()) & 0xFFFFFFFF
	
	pkg_payload = os.path.join(final_path, '%s_%0.8X' % (file_name, file_adler))
	pkg_temp = os.path.join(final_path, '__TEMP_%s_%0.8X' % (file_name, file_adler))
	os.makedirs(pkg_temp)
	
	subprocess.run([anytoiso_path, '/extract', file_path, pkg_temp], check = True, stdout=subprocess.DEVNULL)
		
	if os.path.isfile(os.path.join(pkg_temp, 'Scripts')) :
		scripts_init = os.path.join(pkg_temp, 'Scripts')
		scripts_cpgz = os.path.join(pkg_temp, 'Scripts.cpgz')
		scripts_extr = os.path.join(pkg_temp, 'Scripts', '')
		efi_path = os.path.join(scripts_extr, 'Tools', 'EFIPayloads', '')
		
		os.replace(scripts_init, scripts_cpgz)
		
		subprocess.run([anytoiso_path, '/extract', scripts_cpgz, scripts_extr], check = True, stdout=subprocess.DEVNULL)
		
		shutil.copytree(efi_path, pkg_payload)
		
	elif os.path.isfile(os.path.join(pkg_temp, 'Payload')) :
		payload_init = os.path.join(pkg_temp, 'Payload')
		payload_pbzx = os.path.join(pkg_temp, 'Payload.pbzx')
		payload_extr = os.path.join(pkg_temp, 'Payload', '')
		zip_path = os.path.join(payload_extr, 'usr', 'standalone', 'firmware', 'bridgeOSCustomer.bundle', 'Contents', 'Resources', 'UpdateBundle')
		efi_path = os.path.join(zip_path, 'boot', 'Firmware', 'MacEFI', '')
		
		os.replace(payload_init, payload_pbzx)
		
		subprocess.run([anytoiso_path, '/extract', payload_pbzx, payload_extr], check = True, stdout=subprocess.DEVNULL)
		
		subprocess.run([anytoiso_path, '/extract', zip_path + '.zip', zip_path], check = True, stdout=subprocess.DEVNULL)
		
		if os.path.exists(efi_path) : shutil.copytree(efi_path, pkg_payload)
		
	shutil.rmtree(pkg_temp)
	
	im4p_files = []
	for root, dirs, files in os.walk(pkg_payload):
		for name in files :
			if name.endswith('.im4p') :
				im4p_files.append(os.path.join(root, name))
	
	if im4p_files : subprocess.run(['python', 'Apple_EFI_Split.py', '-skip', *im4p_files], check = True, stdout=subprocess.DEVNULL)
	for im4p in im4p_files : os.remove(im4p)
	
	final_files = []
	for root, dirs, files in os.walk(pkg_payload):
		for name in files :
			final_files.append(os.path.join(root, name))
	
	if final_files : subprocess.run(['python', 'Apple_EFI_Rename.py', '-skip', *final_files], check = True, stdout=subprocess.DEVNULL)
	
	for root, dirs, files in os.walk(pkg_payload):
		for name in files :
			if not os.path.isfile(os.path.join(final_path, name)) :
				shutil.copy2(os.path.join(root, name), os.path.join(final_path, name))
			
	shutil.rmtree(pkg_payload)

else :
	input('\nDone!')