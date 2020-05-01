#!/usr/bin/python3


# MKDecrypt.py (Master Key Decryptor) is a python script to assist with
# decrypting encrypted volumes using the recovered masterkey for various
# truecrypt type encrypted volumes.
# Created by Matt Smith
# email: amnesia_1337 (at) hotmail (dot) co (dot) uk

# Limitations: May produce false negatives if the filesystem used is not one of
# the standard truecrypt/veracrypt formats.  The HFS+ implementation is
# _sketchy_ but appears to work, for now.

import os
import stat
import argparse
import subprocess
import binascii
	
def main():
##	print empty line away from command line so easier for user to read 
	print(' ')

##	Setup arguments/options using imported argparse module
	parser = argparse.ArgumentParser(description='''%(prog)s (Master Key
		Decryptor) is a python script to assist with decrypting
		encrypted volumes using the recovered masterkey for various
		encrypted containers.  Script should be run as root, sudo
		recommended.''', epilog='''Example: [sudo] ./%(prog)s -m /mnt
		truecrypt.tc 123...def''')
	parser.add_argument('-v', '--verbose', action='store_true', help='''
		verbose output''')
	parser.add_argument('-X', '--volatility', action='store_true',
		help='specifies MASTERKEY is a volatility file instead of hex chars')
	rwgroup = parser.add_mutually_exclusive_group()
	rwgroup.add_argument('-r', '--read-only', action='store_true',
		help='opens FILE in read only mode (default)')
	rwgroup.add_argument('-w', '--read-write', action='store_true',
		help='opens FILE in read/write mode')
	parser.add_argument('-m', '--mountpoint', help='''mount encrypted
		volume at MOUNTPOINT''', default='N0P3')
	parser.add_argument('FILE', help='the encrypted container, FILE')
	parser.add_argument('MASTERKEY', help='''the MASTERKEY as a
		hexadecimal string''')
	args = parser.parse_args()
	

##  check to see if you are using a raw volatility dump
	if(args.volatility):
		isMKFile =  os.access(args.MASTERKEY, os.F_OK)
		if isMKFile:
			masterkeyfile = open(args.MASTERKEY,"rb").read()
			args.MASTERKEY = binascii.hexlify(masterkeyfile).decode('utf-8')
		else:
			print (args.MASTERKEY + ' is not a file.' )
			exit(1)


##	check to see if this script is being run as root/superuser. exit if not
	if not os.geteuid() == 0:
		print("This script needs to be run as root/superuser.")
		exit(1)

##	setup ro(read-only) flag for passing to other programs 
	ro = ''
	if not args.read_write:
		args.read_only=True
		ro = '-r'

##	check master key length is correct and is only hex charachters
	if not len(args.MASTERKEY) == 128 and not len(args.MASTERKEY) == 256 and not len(args.MASTERKEY) == 384:
		print('MASTERKEY is not of the correct length.  It should be 128, 256 or 384 hexadecimal characters in length.')
		exit(1)
	hexis = set('0123456789abcdefABCDEF')
	for c in args.MASTERKEY:
		if not c in hexis:
			print ( c + ' is not a hexadecimal character')
			exit(1)

##	check file specified by user actually exists
	isFILE = os.access(args.FILE, os.F_OK)
	if isFILE and args.verbose:
		print (args.FILE + ' exists')
	elif not isFILE:
		print ('No such file: ' + args.FILE)
		exit(1)

##	check mount option and mount point
	if args.mountpoint == 'N0P3':
		mp=False
	else:
		isDIR = os.path.isdir(args.mountpoint)
		if isDIR and args.verbose:
			print(args.mountpoint + ' exists')
		elif not isDIR:
			print('No such mountpoint: ' + args.mountpoint)
			exit(1)
		mp=True

##	find a free MKDecrypt device mapper slot
	for i in range(8):
		dmname = "MKDecrypt" + str(i+1)
		dmslot = "/dev/mapper/" + dmname
		takenslot = os.access(dmslot, os.F_OK)
		if not takenslot:
			break
		elif i == 7:
			print('All 8 MKDecrypt slots are taken!  Free some up.')
			exit(1)

##	check to see if container is already a blockdev
##	if so, skip mounting it as loop device
	mode=os.lstat(args.FILE).st_mode
	isBLKDEV = stat.S_ISBLK(mode)
	if isBLKDEV:
		loopdev = args.FILE
##	otherwise mount container as loop device
	else:
		losetupcmd = 'losetup ' + ro + ' -f --show ' + args.FILE
		losetupoutput = subprocess.check_output(losetupcmd, shell=True, universal_newlines=True)
		loopdev = losetupoutput[:-1]
		if args.verbose:
			print (loopdev + ' has been setup as loop device of ' + args.FILE)
			
##	get size in sectors of FILE and remove 512 sectors from the size.
##	512 sectors is from Truecrypt header (256 sectors at start of file)
##	+ backup header (256 sectors at end of file)
	evsize = int(subprocess.check_output(['blockdev', '--getsz', loopdev])) - 512
	extevrange = evsize - 3

##	Define binary values for OEMs (VBR) for later test
	binMSDOS	= str.encode('MSDOS')
	binMSWIN	= str.encode('MSWIN')
	binEXFAT	= str.encode('EXFAT')
	binNTFS		= str.encode('NTFS ')
	binMKDOS	= str.encode('mkdos')
	binIBM		= str.encode('IBM  ')
	binFREEDOS	= str.encode('FreeD')
	binMKFS		= str.encode('mkfs.')
	
##	define binary values for Ext and HFS+ tests and setup flags for use after test
##	set j=0 for all filesystems except HFS+ (changed later for HFS+)
	binExtSig	= binascii.a2b_hex('53ef')
	bin000000	= binascii.a2b_hex('000000')
	binHFSJ		= str.encode('H+')
	binHFSX		= str.encode('HX')
	isExt		= False
	isHFSP		= False
	j		= 0
	
##	if not cascaded encryption
	if len(args.MASTERKEY) == 128:
		crypts = [' aes-xts-plain64 ', ' serpent-xts-plain64 ', ' twofish-xts-plain64 ', ' camellia-xts-plain64 ', ' kuznyechik-xts-plain64 ']
##		first check if normal/outer volume 
		tryhiddenvol = False
		for crypt in crypts:
##			create table entry for dmsetup command
			table =  '"0 ' + str(evsize) + ' crypt' + crypt + args.MASTERKEY + ' 256 ' + loopdev + ' 256"'
##			create dmsetup command ready to pass to shell, then pass it			
			dmsetupcmd = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table
			subprocess.call(dmsetupcmd, shell=True)
##			test that the volume has decrypted correctly by reading (part of) the OEM from VBR
			try:
				test = open(dmslot, 'rb')
##			in case dmslot not found error
			except IOError:
				print("io error! decrypt failed! try another one")
				if crypt == ' kuznyechik-xts-plain64 ':
##					if all encryption types have been tried then try hidden volumes
					tryhiddenvol = True
				continue
			test.seek(3)
			OEM = test.read(5)
			test.seek(1024)
			HFSPSig = test.read(2)
			test.seek(1080)
			ExtSig = test.read(2)
			test.seek(1097)
			ExtOS = test.read(3)
			test.seek(1120)
			FIARes = test.read(3)
			test.close()
			if ExtSig == binExtSig and ExtOS == bin000000:
				isExt = True
			elif HFSPSig == binHFSJ and FIARes == bin000000:
				isHFSP = True
			elif HFSPSig == binHFSX and FIARes == bin000000:
				isHFSP = True
			if OEM == binMSDOS or OEM == binMSWIN or OEM == binEXFAT or OEM == binNTFS or OEM == binMKDOS or OEM == binIBM or OEM == binFREEDOS or OEM == binMKFS or isExt or isHFSP:
				print('Normal/outer volume found in ' + args.FILE + ' using' + crypt)
				break
##			if it hasn't worked remove device mapping
			else:
				rmdecfile = 'dmsetup remove ' + dmname
				subprocess.call(rmdecfile, shell=True)
				if crypt == ' kuznyechik-xts-plain64 ':
##					if all encryption types have been tried then try hidden volumes
					tryhiddenvol = True
		if tryhiddenvol:
			print ('Masterkey does not decrypt a normal/outer volume.  Trying for a hidden volume...')
			for crypt in crypts:
##				create table entry for dmsetup command
				table =  '"0 ' + str(evsize) + ' crypt' + crypt + args.MASTERKEY + ' 256 ' + loopdev + ' 256"'
##				create dmsetup command ready to pass to shell, then pass it			
				dmsetupcmd = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table
				subprocess.call(dmsetupcmd, shell=True)
##				search for OEM which indicates where hidden volume VBR is located within the container
				search = open(dmslot, 'rb')
				for i in range(evsize):
##					provide the user with an update every 100,000 sectors
					if (i % 100000) == 0 :
						print('Scanning byte ' + str(i*512) + ' of ' + str(evsize*512) + ' using' + crypt, end='                \r') 
					search.seek((i*512)+3)
					srchOEM = search.read(5)
					if i <= (extevrange):
						search.seek((i*512)+1024)
						srchHFSPSig = search.read(2)
						search.seek((i*512)+1080)
						srchExtSig = search.read(2)
						search.seek((i*512)+1097)
						srchExtOS = search.read(3)
						search.seek((i*512)+1120)
						srchFIARes = search.read(3)
						if srchExtSig == binExtSig and srchExtOS == bin000000:
							isExt = True
						elif srchHFSPSig == binHFSJ and srchFIARes == bin000000:
							isHFSP = True
						elif srchHFSPSig == binHFSX and srchFIARes == bin000000:
							isHFSP = True
##					Linux HSF+ driver fails if backup header is not where expected
##					so find backup header before attempting to mount...
					if isHFSP:
						print('HFS+ filesystem found. Searching for backup volume header...                                                                     ')
						for j in range (evsize-i):
							search.seek((evsize - j)*512 - 1024)
							bckHFSPSig = search.read(2)
							search.seek((evsize - j)*512 - 928)
							bckFIARes = search.read(3)
							if bckHFSPSig == binHFSJ and bckFIARes == bin000000:
								break
							elif bckHFSPSig == binHFSX and bckFIARes == bin000000:
								break
							elif j == (evsize-i)-5:
								search.close()
								rmdmcmd = 'dmsetup remove ' + dmname
								subprocess.call(rmdmcmd, shell=True)
								if not isBLKDEV:
									subprocess.call(['losetup', '-d', loopdev])
								print('Unable to find backup volume header.  Is volume corrupted?')
								exit(1)
					if srchOEM == binMSDOS or srchOEM == binMSWIN or srchOEM == binEXFAT or srchOEM == binNTFS or srchOEM == binMKDOS or srchOEM == binIBM or srchOEM == binFREEDOS or srchOEM == binMKFS or isExt or isHFSP:
						search.close()
						print('Hidden volume found ' + str((i+256)*512) + ' bytes into ' + args.FILE + ' using' + crypt)
						rmdmcmd = 'dmsetup remove ' + dmname
						subprocess.call(rmdmcmd, shell=True)
						table = '"0 ' + str(evsize-(i+j)) + ' crypt' + crypt + args.MASTERKEY + ' ' + str(i+256) + ' ' + loopdev + ' ' + str(i+256) + '"'
						dmsetupcmd = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table
						subprocess.call(dmsetupcmd, shell=True)
						break
					elif i == evsize-1:
						search.close()
						rmdmcmd = 'dmsetup remove ' + dmname
						subprocess.call(rmdmcmd, shell=True)
						if crypt == ' kuznyechik-xts-plain64 ':
							if not isBLKDEV:
								subprocess.call(['losetup', '-d', loopdev])
							print('No volume decrypted in ' + args.FILE + '.  Is masterkey correct?')
							exit(1)
				if srchOEM == binMSDOS or srchOEM == binMSWIN or srchOEM == binEXFAT or srchOEM == binNTFS or srchOEM == binMKDOS or srchOEM == binIBM or srchOEM == binFREEDOS or srchOEM == binMKFS or isExt or isHFSP:
					break

##	if a 2 cascaded enryption type
	if len(args.MASTERKEY) == 256:
##		split masterkey into 2
		MK1 = args.MASTERKEY[128:]
		MK2 = args.MASTERKEY[:128]
		crypts = ['aes-twofish', 'camellia-kuznyechik', 'camellia-serpent', 'kuznyechik-aes', 'kuznyechik-twofish', 'serpent-aes', 'twofish-serpent']
		tryhiddenvol = False
##		first check for normal/outer volume
		for crypt in crypts:
			if crypt == 'aes-twofish':
				EN1 = ' aes-xts-plain64 '
				EN2 = ' twofish-xts-plain64 '
			elif crypt == 'camellia-kuznyechik':
				EN1 = ' camellia-xts-plain64 '
				EN2 = ' kuznyechik-xts-plain64 '
			elif crypt == 'camellia-serpent':
				EN1 = ' camellia-xts-plain64 '
				EN2 = ' serpent-xts-plain64 '
			elif crypt == 'kuznyechik-aes':
				EN1 = ' kuznyechik-xts-plain64 '
				EN2 = ' aes-xts-plain64 '
			elif crypt == 'kuznyechik-twofish':
				EN1 = ' kuznyechik-xts-plain64 '
				EN2 = ' twofish-xts-plain64 '
			elif crypt == 'serpent-aes':
				EN1 = ' serpent-xts-plain64 '
				EN2 = ' aes-xts-plain64 '
			elif crypt == 'twofish-serpent':
				EN1 = ' twofish-xts-plain64 '
				EN2 = ' serpent-xts-plain64 '
			table1 = '"0 ' + str(evsize) + ' crypt' + EN1 + MK1 + ' 256 ' + loopdev + ' 256"'
			table2 = '"0 ' + str(evsize) + ' crypt' + EN2 + MK2 + ' 256 ' + dmslot + '_1 0"'
			dmsetupcmd1 = 'dmsetup create ' + dmname + '_1 ' + ro + ' --table ' + table1
			dmsetupcmd2 = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table2
			subprocess.call(dmsetupcmd1, shell=True)
			subprocess.call(dmsetupcmd2, shell=True)
##			test that the volume has decrypted correctly by reading (part of) the OEM from VBR
			test = open(dmslot, 'rb')
			test.seek(3)
			OEM = test.read(5)
			test.seek(1024)
			HFSPSig = test.read(2)
			test.seek(1080)
			ExtSig = test.read(2)
			test.seek(1097)
			ExtOS = test.read(3)
			test.seek(1120)
			FIARes = test.read(3)
			test.close()
			if ExtSig == binExtSig and ExtOS == bin000000:
				isExt = True
			elif HFSPSig == binHFSJ and FIARes == bin000000:
				isHFSP = True
			elif HFSPSig == binHFSX and FIARes == bin000000:
				isHFSP = True
			if OEM == binMSDOS or OEM == binMSWIN or OEM == binEXFAT or OEM == binNTFS or OEM == binMKDOS or OEM == binIBM or OEM == binFREEDOS or OEM == binMKFS or isExt or isHFSP:
				print('Normal/outer volume found in '+ args.FILE + ' using' + EN1 + 'then' + EN2)
				break
##			if it hasn't worked remove device mapping
			else:
				rmdecfile1 = 'dmsetup remove ' + dmname
				rmdecfile2 = 'dmsetup remove ' + dmname + '_1'
				subprocess.call(rmdecfile1, shell=True)
				subprocess.call(rmdecfile2, shell=True)
##				if not normal volume check entire container for a hidden volume
				if crypt == 'twofish-serpent':
					tryhiddenvol = True
		if tryhiddenvol:
			print ('Masterkey does not decrypt a normal/outer volume.  Trying for a hidden volume...')
			for crypt in crypts:
				if crypt == 'aes-twofish':
					EN1 = ' aes-xts-plain64 '
					EN2 = ' twofish-xts-plain64 '
				elif crypt == 'camellia-kuznyechik':
					EN1 = ' camellia-xts-plain64 '
					EN2 = ' kuznyechik-xts-plain64 '
				elif crypt == 'camellia-serpent':
					EN1 = ' camellia-xts-plain64 '
					EN2 = ' serpent-xts-plain64 '
				elif crypt == 'kuznyechik-aes':
					EN1 = ' kuznyechik-xts-plain64 '
					EN2 = ' aes-xts-plain64 '
				elif crypt == 'kuznyechik-twofish':
					EN1 = ' kuznyechik-xts-plain64 '
					EN2 = ' twofish-xts-plain64 '
				elif crypt == 'serpent-aes':
					EN1 = ' serpent-xts-plain64 '
					EN2 = ' aes-xts-plain64 '
				elif crypt == 'twofish-serpent':
					EN1 = ' twofish-xts-plain64 '
					EN2 = ' serpent-xts-plain64 '
				table1 = '"0 ' + str(evsize) + ' crypt' + EN1 + MK1 + ' 256 ' + loopdev + ' 256"'
				table2 = '"0 ' + str(evsize) + ' crypt' + EN2 + MK2 + ' 256 ' + dmslot + '_1 0"'
				dmsetupcmd1 = 'dmsetup create ' + dmname + '_1 ' + ro + ' --table ' + table1
				dmsetupcmd2 = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table2
				subprocess.call(dmsetupcmd1, shell=True)
				subprocess.call(dmsetupcmd2, shell=True)
##				search for OEM which indicates where hidden volume VBR is located within the container
				search = open(dmslot, 'rb')
				for i in range(evsize):
##					provide the user with an update every 100,000 sectors
					if (i % 100000) == 0 :
						print('Scanning byte ' + str(i*512) + ' of ' + str(evsize*512) + ' using' + EN1 + 'then' + EN2, end='                \r') 
					search.seek((i*512)+3)
					srchOEM = search.read(5)
					if i <= extevrange:
						search.seek((i*512)+1024)
						srchHFSPSig = search.read(2)
						search.seek((i*512)+1080)
						srchExtSig = search.read(2)
						search.seek((i*512)+1097)
						srchExtOS = search.read(3)
						search.seek((i*512)+1120)
						srchFIARes = search.read(3)
						if srchExtSig == binExtSig and srchExtOS == bin000000:
							isExt = True
						elif srchHFSPSig == binHFSJ and srchFIARes == bin000000:
							isHFSP = True
						elif srchHFSPSig == binHFSX and srchFIARes == bin000000:
							isHFSP = True
##					Linux HSF+ driver fails if backup header is not where expected
##					so find backup header before attempting to mount...
					if isHFSP:
						print('HFS+ filesystem found. Searching for backup volume header...                                                                     ')
						for j in range (evsize-i):
							search.seek((evsize - j)*512 - 1024)
							bckHFSPSig = search.read(2)
							search.seek((evsize - j)*512 - 928)
							bckFIARes = search.read(3)
							if bckHFSPSig == binHFSJ and bckFIARes == bin000000:
								break
							elif bckHFSPSig == binHFSX and bckFIARes == bin000000:
								break
							elif j == (evsize-i)-5:
								search.close()
								rmdmcmd1 = 'dmsetup remove ' + dmname
								rmdmcmd2 = 'dmsetup remove ' + dmname + '_1'
								subprocess.call(rmdmcmd1, shell=True)
								subprocess.call(rmdmcmd2, shell=True)
								if not isBLKDEV:
									subprocess.call(['losetup', '-d', loopdev])
								print('Unable to find backup volume header.  Is volume corrupted?')
								exit(1)
					if srchOEM == binMSDOS or srchOEM == binMSWIN or srchOEM == binEXFAT or srchOEM == binNTFS or srchOEM == binMKDOS or srchOEM == binIBM or srchOEM == binFREEDOS or srchOEM == binMKFS or isExt or isHFSP:
						search.close()
						print('Hidden volume found ' + str((i+256)*512) + ' bytes into ' + args.FILE + ' using' + EN1 + 'then' + EN2 )
						rmdmcmd1 = 'dmsetup remove ' + dmname
						rmdmcmd2 = 'dmsetup remove ' + dmname + '_1'
						subprocess.call(rmdmcmd1, shell=True)
						subprocess.call(rmdmcmd2, shell=True)
						table1 = '"0 ' + str(evsize-(i+j)) + ' crypt' + EN1 + MK1 + ' ' + str(i+256) + ' ' + loopdev + ' ' + str(i+256) + '"'
						table2 = '"0 ' + str(evsize-(i+j)) + ' crypt' + EN2 + MK2 + ' ' + str(i+256) + ' ' + dmslot + '_1 0"'
						dmsetupcmd1 = 'dmsetup create ' + dmname + '_1 ' + ro + ' --table ' + table1
						dmsetupcmd2 = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table2
						subprocess.call(dmsetupcmd1, shell=True)
						subprocess.call(dmsetupcmd2, shell=True)
						break
					elif i == evsize-1:
						search.close()
						rmdmcmd1 = 'dmsetup remove ' + dmname
						rmdmcmd2 = 'dmsetup remove ' + dmname + '_1'
						subprocess.call(rmdmcmd1, shell=True)
						subprocess.call(rmdmcmd2, shell=True)
						if crypt == 'twofish-serpent':
							if not isBLKDEV:
								subprocess.call(['losetup', '-d', loopdev])
							print('No volume decrypted in ' + args.FILE + '.  Is masterkey correct?')
							exit(1)
				if srchOEM == binMSDOS or srchOEM == binMSWIN or srchOEM == binEXFAT or srchOEM == binNTFS or srchOEM == binMKDOS or srchOEM == binIBM or srchOEM == binFREEDOS or srchOEM == binMKFS or isExt or isHFSP:
					break

##	if a 3 cascaded enryption type
	if len(args.MASTERKEY) == 384:
##		split masterkeys into 3
		MK1 = args.MASTERKEY[256:]
		MK2 = args.MASTERKEY[128:256]
		MK3 = args.MASTERKEY[:128]
		crypts = ['aes-twofish-serpent', 'kuznyechik-serpent-camellia', 'serpent-twofish-aes']
		tryhiddenvol = False
##		first check for normal/outer volume
		for crypt in crypts:
			if crypt == 'aes-twofish-serpent':
				EN1 = ' aes-xts-plain64 '
				EN2 = ' twofish-xts-plain64 '
				EN3 = ' serpent-xts-plain64 '
			elif crypt == 'kuznyechik-serpent-camellia':
				EN1 = ' kuznyechik-xts-plain64 '
				EN2 = ' serpent-xts-plain64 '
				EN3 = ' camellia-xts-plain64 '
			elif crypt == 'serpent-twofish-aes':
				EN1 = ' serpent-xts-plain64 '
				EN2 = ' twofish-xts-plain64 '
				EN3 = ' aes-xts-plain64 '
			table1 = '"0 ' + str(evsize) + ' crypt' + EN1 + MK1 + ' 256 ' + loopdev + ' 256"'
			table2 = '"0 ' + str(evsize) + ' crypt' + EN2 + MK2 + ' 256 ' + dmslot + '_2 0"'
			table3 = '"0 ' + str(evsize) + ' crypt' + EN3 + MK3 + ' 256 ' + dmslot + '_1 0"'
			dmsetupcmd1 = 'dmsetup create ' + dmname + '_2 ' + ro + ' --table ' + table1
			dmsetupcmd2 = 'dmsetup create ' + dmname + '_1 ' + ro + ' --table ' + table2
			dmsetupcmd3 = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table3
			subprocess.call(dmsetupcmd1, shell=True)
			subprocess.call(dmsetupcmd2, shell=True)
			subprocess.call(dmsetupcmd3, shell=True)
##			test that the volume has decrypted correctly by reading (part of) the OEM from VBR
			test = open(dmslot, 'rb')
			test.seek(3)
			OEM = test.read(5)
			test.seek(1024)
			HFSPSig = test.read(2)
			test.seek(1080)
			ExtSig = test.read(2)
			test.seek(1097)
			ExtOS = test.read(3)
			test.seek(1120)
			FIARes = test.read(3)
			test.close()
			if ExtSig == binExtSig and ExtOS == bin000000:
				isExt = True
			elif HFSPSig == binHFSJ and FIARes == bin000000:
				isHFSP = True
			elif HFSPSig == binHFSX and FIARes == bin000000:
				isHFSP = True
			if OEM == binMSDOS or OEM == binMSWIN or OEM == binEXFAT or OEM == binNTFS or OEM == binMKDOS or OEM == binIBM or OEM == binFREEDOS or OEM == binMKFS or isExt or isHFSP:
				print('Normal/outer volume found in ' + args.FILE + ' using' + EN1 + 'then' + EN2 + 'then' + EN3)
				break
##			if it hasn't worked remove device mapping
			else:
				rmdecfile1 = 'dmsetup remove ' + dmname
				rmdecfile2 = 'dmsetup remove ' + dmname + '_1'
				rmdecfile3 = 'dmsetup remove ' + dmname + '_2'
				subprocess.call(rmdecfile1, shell=True)
				subprocess.call(rmdecfile2, shell=True)
				subprocess.call(rmdecfile3, shell=True)
##				if not normal volume check entire container for a hidden volume
				if crypt == 'serpent-twofish-aes':
					tryhiddenvol = True
		if tryhiddenvol:
			print ('Masterkey does not decrypt a normal/outer volume.  Trying for a hidden volume...')
			for crypt in crypts:
				if crypt == 'aes-twofish-serpent':
					EN1 = ' aes-xts-plain64 '
					EN2 = ' twofish-xts-plain64 '
					EN3 = ' serpent-xts-plain64 '
				elif crypt == 'kuznyechik-serpent-camellia':
					EN1 = ' kuznyechik-xts-plain64 '
					EN2 = ' serpent-xts-plain64 '
					EN3 = ' camellia-xts-plain64 '
				elif crypt == 'serpent-twofish-aes':
					EN1 = ' serpent-xts-plain64 '
					EN2 = ' twofish-xts-plain64 '
					EN3 = ' aes-xts-plain64 '
				table1 = '"0 ' + str(evsize) + ' crypt' + EN1 + MK1 + ' 256 ' + loopdev + ' 256"'
				table2 = '"0 ' + str(evsize) + ' crypt' + EN2 + MK2 + ' 256 ' + dmslot + '_2 0"'
				table3 = '"0 ' + str(evsize) + ' crypt' + EN3 + MK3 + ' 256 ' + dmslot + '_1 0"'
				dmsetupcmd1 = 'dmsetup create ' + dmname + '_2 ' + ro + ' --table ' + table1
				dmsetupcmd2 = 'dmsetup create ' + dmname + '_1 ' + ro + ' --table ' + table2
				dmsetupcmd3 = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table3
				subprocess.call(dmsetupcmd1, shell=True)
				subprocess.call(dmsetupcmd2, shell=True)
				subprocess.call(dmsetupcmd3, shell=True)	
##				search truecrypthidden for OEM which indicates where hidden volume VBR is
				search = open(dmslot, 'rb')
				for i in range(evsize):
##					provide the user with an update every 100,000 sectors
					if (i % 100000) == 0 :
						print('Scanning byte ' + str(i*512) + ' of ' + str(evsize*512) + ' using' + EN1 + 'then' + EN2 + 'then' + EN3, end='                \r') 
					search.seek((i*512)+3)
					srchOEM = search.read(5)
					if i <= (extevrange):
						search.seek((i*512)+1024)
						srchHFSPSig = search.read(2)
						search.seek((i*512)+1080)
						srchExtSig = search.read(2)
						search.seek((i*512)+1097)
						srchExtOS = search.read(3)
						search.seek((i*512)+1120)
						srchFIARes = search.read(3)
						if srchExtSig == binExtSig and srchExtOS == bin000000:
							isExt = True
						elif srchHFSPSig == binHFSJ and srchFIARes == bin000000:
							isHFSP = True
						elif srchHFSPSig == binHFSX and srchFIARes == bin000000:
							isHFSP = True
##					Linux HSF+ driver fails if backup header is not where expected
##					so find backup header before attempting to mount...
					if isHFSP:
						print('HFS+ filesystem found. Searching for backup volume header...                                                                     ')
						for j in range (evsize-i):
							search.seek((evsize - j)*512 - 1024)
							bckHFSPSig = search.read(2)
							search.seek((evsize - j)*512 - 928)
							bckFIARes = search.read(3)
							if bckHFSPSig == binHFSJ and bckFIARes == bin000000:
								break
							elif bckHFSPSig == binHFSX and bckFIARes == bin000000:
								break
							elif j == (evsize-i)-5:
								search.close()
								rmdmcmd1 = 'dmsetup remove ' + dmname
								rmdmcmd2 = 'dmsetup remove ' + dmname + '_1'
								rmdmcmd3 = 'dmsetup remove ' + dmname + '_2'
								subprocess.call(rmdmcmd1, shell=True)
								subprocess.call(rmdmcmd2, shell=True)
								subprocess.call(rmdmcmd3, shell=True)
								if not isBLKDEV:
									subprocess.call(['losetup', '-d', loopdev])
								print('Unable to find backup volume header.  Is volume corrupted?')
								exit(1)
					if srchOEM == binMSDOS or srchOEM == binMSWIN or srchOEM == binEXFAT or srchOEM == binNTFS or srchOEM == binMKDOS or srchOEM == binIBM or srchOEM == binFREEDOS or srchOEM == binMKFS or isExt or isHFSP:
						search.close()
						print('Hidden volume found ' + str((i+256)*512) + ' bytes into ' + args.FILE + ' using' + EN1 + 'then' + EN2 + 'then' + EN3)
						rmdmcmd1 = 'dmsetup remove ' + dmname
						rmdmcmd2 = 'dmsetup remove ' + dmname + '_1'
						rmdmcmd3 = 'dmsetup remove ' + dmname + '_2'
						subprocess.call(rmdmcmd1, shell=True)
						subprocess.call(rmdmcmd2, shell=True)
						subprocess.call(rmdmcmd3, shell=True)
						table1 = '"0 ' + str(evsize-(i+j)) + ' crypt' + EN1 + MK1 + ' ' + str(i+256) + ' ' + loopdev + ' ' + str(i+256) + '"'
						table2 = '"0 ' + str(evsize-(i+j)) + ' crypt' + EN2 + MK2 + ' ' + str(i+256) + ' ' + dmslot + '_2 0"'
						table3 = '"0 ' + str(evsize-(i+j)) + ' crypt' + EN3 + MK3 + ' ' + str(i+256) + ' ' + dmslot + '_1 0"'
						dmsetupcmd1 = 'dmsetup create ' + dmname + '_2 ' + ro + ' --table ' + table1
						dmsetupcmd2 = 'dmsetup create ' + dmname + '_1 ' + ro + ' --table ' + table2
						dmsetupcmd3 = 'dmsetup create ' + dmname + ' ' + ro + ' --table ' + table3
						subprocess.call(dmsetupcmd1, shell=True)
						subprocess.call(dmsetupcmd2, shell=True)
						subprocess.call(dmsetupcmd3, shell=True)
						break
					elif i == evsize-1:
						search.close()
						rmdmcmd1 = 'dmsetup remove ' + dmname
						rmdmcmd2 = 'dmsetup remove ' + dmname + '_1'
						rmdmcmd3 = 'dmsetup remove ' + dmname + '_2'
						subprocess.call(rmdmcmd1, shell=True)
						subprocess.call(rmdmcmd2, shell=True)
						subprocess.call(rmdmcmd3, shell=True)
						if crypt == 'serpent-twofish-aes':
							if not isBLKDEV:
								subprocess.call(['losetup', '-d', loopdev])
							print('No volume decrypted in ' + args.FILE + '.  Is masterkey correct?')
							exit(1)
				if srchOEM == binMSDOS or srchOEM == binMSWIN or srchOEM == binEXFAT or srchOEM == binNTFS or srchOEM == binMKDOS or srchOEM == binIBM or srchOEM == binFREEDOS or srchOEM == binMKFS or isExt or isHFSP:
					break
		
	
##	if requested, mount the decrypted volume
	if mp:
		mountcmd = 'mount ' + ro + ' ' + dmslot + ' ' + args.mountpoint
		subprocess.call(mountcmd, shell=True)
		print(args.FILE + ' has been decrypted at ' + dmslot + ' and mounted at ' + args.mountpoint)
	else:
		print(args.FILE + ' is decrypted at ' + dmslot)


##	pause until user presses enter while also checking that
##	mount and device mapping are no longer being used
	mount=True
	while mount:
		while mount:
			input('Once done, press Enter to dismount ' + args.FILE + '...')
			if mp:
				umountcmd = 'umount ' + dmslot
				check = subprocess.call(umountcmd, shell=True, stderr=subprocess.DEVNULL)
				if not check == 0:
					print(args.mountpoint + " is still in use!")
					break
				elif args.verbose:
					print("Unmounted from " + args.mountpoint)
			if len(args.MASTERKEY) >= 128:
				rmdmcmd = 'dmsetup remove ' + dmname
				check = subprocess.call(rmdmcmd, shell=True, stderr=subprocess.DEVNULL)	
				if not check == 0:
					print("Device mapping: " + dmslot + " is still in use!")
					break
				else:
					if args.verbose:
						print("Removed device mapping: " + dmslot)
					if len(args.MASTERKEY) == 128:
						mount=False
			if len(args.MASTERKEY) >= 256:
				rmdmcmd = 'dmsetup remove ' + dmname + '_1'
				subprocess.call(rmdmcmd, shell=True, stderr=subprocess.DEVNULL)
				if len(args.MASTERKEY) == 256:
					mount=False
			if len(args.MASTERKEY) == 384:
				rmdmcmd = 'dmsetup remove ' + dmname + '_2'
				subprocess.call(rmdmcmd, shell=True, stderr=subprocess.DEVNULL)
				mount=False
	
	if not isBLKDEV:
		subprocess.call(['losetup', '-d', loopdev])
		if args.verbose:
			print("Removed loop device: " + loopdev) 


if __name__ == '__main__':
	main()
