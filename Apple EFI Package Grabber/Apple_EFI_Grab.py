#!/usr/bin/env python3
#coding=utf-8

"""
Apple EFI Grab
Apple EFI Package Grabber
Copyright (C) 2018-2021 Plato Mavropoulos
"""

title = 'Apple EFI Package Grabber v2.0'

print('\n' + title)

import sys

sys_ver = sys.version_info
if sys_ver < (3,7):
    sys.stdout.write('\n\nError: Python >= 3.7 required, not %d.%d!\n' % (sys_ver[0], sys_ver[1]))
    (raw_input if sys_ver[0] <= 2 else input)('\nPress enter to exit') # pylint: disable=E0602
    sys.exit(1)

import traceback

def show_exception_and_exit(exc_type, exc_value, tb):
    if exc_type is KeyboardInterrupt:
        print('\nNote: Keyboard Interrupt!')
    else:
        print('\nError: %s crashed, please report the following:\n' % title)
        traceback.print_exception(exc_type, exc_value, tb)
        input('\nPress enter to exit')
    
    sys.exit(1)

sys.excepthook = show_exception_and_exit

import datetime
import urllib.request
from multiprocessing.pool import ThreadPool

def fetch_cat_info(name):
    url = cat_url[:-len('others/')] + name if name in ['index.sucatalog','index-1.sucatalog'] else cat_url + name
    with urllib.request.urlopen(urllib.request.Request(url, method='HEAD')) as head : mod = head.headers['last-modified']
    
    return name, url, mod

def fetch_cat_links(cat_file):
    cat_links = []
    
    with urllib.request.urlopen(cat_file[1]) as link: fdata = link.readlines()
    
    cat_lines = [l.decode('utf-8').strip('\n') for l in fdata]
    
    for line in cat_lines:
        if ('.pkg' in line or '.tar' in line) and ('FirmwareUpd' in line or '/BridgeOSUpdateCustomer' in line or 'EFIUpd' in line) \
        and 'Bluetooth' not in line and 'DPVGA' not in line and 'Thunderbolt' not in line and 'PMG5' not in line and 'HardDrive' not in line:
            down_link = line[line.find('http'):(line.find('.pkg') if '.pkg' in line else line.find('.tar')) + 4]
            down_link = down_link.replace('http:','https:')
            cat_links.append(down_link)
    
    return cat_links

dat_db = 'Apple_EFI_Grab.dat'
cat_url = 'https://swscan.apple.com/content/catalogs/others/'
apple_cat = []
down_links = []
svr_date = None
thread_num = 2

with open(dat_db, 'r', encoding='utf-8') as dat: db_lines = dat.readlines()
db_lines = [line.strip('\n') for line in db_lines]

db_date = datetime.datetime.strptime(db_lines[0], '%Y-%m-%d %H:%M:%S')
db_links = set([line for line in db_lines if line.startswith('https')])
db_sucat = [line for line in db_lines if line.startswith('index')]

print('\nGetting Catalog Listing...')

if not db_sucat:
    input('\nError: Failed to retrieve Catalogs from DB!\n\nDone!')
    sys.exit(1)

apple_mod = ThreadPool(thread_num).imap_unordered(fetch_cat_info, db_sucat)

for name, url, mod in apple_mod:
    dt = datetime.datetime.strptime(mod, '%a, %d %b %Y %H:%M:%S %Z')
    if not svr_date or dt > svr_date : svr_date = dt
    
    apple_cat.append((name, url, dt))

if not svr_date:
    input('\nError: Failed to retrieve Current Catalog Datetime!\n\nDone!')
    sys.exit(1)

print('\n    Previous Catalog Datetime :', db_date)
print('    Current Catalog Datetime  :', svr_date)

if svr_date <= db_date:
    input('\nNothing new since %s!\n\nDone!' % db_date)
    sys.exit()

print('\nGetting Catalog Links...')

down_links = ThreadPool(thread_num).imap_unordered(fetch_cat_links, apple_cat)
down_links = [item for sublist in down_links for item in sublist]

if not down_links:
    input('\nError: Failed to retrieve Catalog Links!\n\nDone!')
    sys.exit(1)

new_links = sorted(list(dict.fromkeys([link for link in down_links if link not in db_links])))

if new_links:
    print('\nFound %d new link(s) between %s and %s!' % (len(new_links), db_date, svr_date))
    
    cur_date = datetime.datetime.utcnow().isoformat(timespec='seconds').replace('-','').replace('T','').replace(':','') # Local UTC Unix
    
    with open('Apple_%s.txt' % cur_date, 'w', encoding='utf-8') as lout: lout.write('\n'.join(map(str, new_links)))
else:
    print('\nThere are no new links between %s and %s!' % (db_date, svr_date))

new_db_sucat = '\n'.join(map(str, db_sucat))

new_db_links = '\n'.join(map(str, sorted(list(dict.fromkeys(down_links)))))

new_db_lines = '%s\n\n%s\n\n%s' % (svr_date, new_db_sucat, new_db_links)

with open(dat_db, 'w', encoding='utf-8') as dbout: dbout.write(new_db_lines)

input('\nDone!')