#!/usr/bin/python3


# FDMKDec.py (Full Disc Master Key Decryptor) is a python script to assist
# with decrypting full disk system encrypted drives using the recovered
# masterkey for various truecrypt type encrypted disks.
# Created by Matt Smith
# email: amnesia_1337 (at) hotmail (dot) co (dot) uk

# Limitations: May produce false negatives if the filesystem used is not
# one of the standard formats.

import sys
import os
import stat
import argparse
import subprocess
import binascii
import time
	
def main():
##	print empty line away from command line so easier for user to read 
	print(' ')

##	Setup arguments/options using imported argparse module
	parser = argparse.ArgumentParser(description='''%(prog)s (Full Disk 
		Master Key Decryptor) is a python script to assist with
		decrypting full disk system encrypted drives using the
		recovered masterkey for various encrypted disks.  Script
		should be run as root, sudo recommended.''', epilog='''
		Example: [sudo] ./%(prog)s -m /mnt truecrypt.tc 123...def
		''')
	parser.add_argument('-v', '--verbose', action='store_true', help='''
		verbose output''')
	rwgroup = parser.add_mutually_exclusive_group()
	rwgroup.add_argument('-r', '--read-only', action='store_true',
		help='opens FILE in read only mode (default)')
	rwgroup.add_argument('-w', '--read-write', action='store_true',
		help='opens FILE in read/write mode')
	parser.add_argument('-m', '--mountpoint', help='''mount encrypted
		volume at MOUNTPOINT''', default='N0P3')
	parser.add_argument('FILE', help='the encrypted disk or disk image, FILE')
	parser.add_argument('MASTERKEY', help='''the MASTERKEY as a
		hexadecimal string''')
	args = parser.parse_args()
	
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
		dmname = "FDMKDec" + str(i+1)
		dmslot = "/dev/mapper/" + dmname
		dmslot0 = dmslot + '_0'
		takenslot = os.access(dmslot, os.F_OK)
		if not takenslot:
			break
		elif i == 7:
			print('All 8 FDMKDec slots are taken!  Free some up.')
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
			
##	get size in sectors of FILE and remove 63 sectors from the size.
##	The first 62 sectors contain an unencrypted truecrypt/veracrypt
##	bootloader.  Sector 62 cotains the header information which is
##	encrypted using a seperate password derived key (not needed as
##	we already have the masterkey)
	evsize = int(subprocess.check_output(['blockdev', '--getsz', loopdev])) - 63

##	Find the starting sector for the first partition.
##	Send errors to NULL because if the disk has logical partitions
##	these additional partition tables will still be encrypted and
##	so partx will not correctly read them until decrypted.
	partxout = subprocess.check_output(['partx', '-g', '--nr', '1', '-o', 'START', loopdev], universal_newlines=True, stderr=subprocess.DEVNULL)
	firstpart = int(partxout[:-1])

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
		crypts = [' aes-xts-plain64 ', ' serpent-xts-plain64 ', ' twofish-xts-plain64 ', ' camellia-xts-plain64 ']
##		first check if normal/outer volume 
		for crypt in crypts:
##			create table entry for dmsetup command
			table =  '"0 ' + str(evsize) + ' crypt' + crypt + args.MASTERKEY + ' 63 ' + loopdev + ' 63"'
##			create dmsetup command ready to pass to shell, then pass it			
			dmsetupcmd1 = 'dmsetup create ' + dmname + '_0 ' + ro + ' --table ' + table
			subprocess.call(dmsetupcmd1, shell=True)
##			test that the volume has decrypted correctly by reading (part of) the OEM from VBR of the first partition
			test = open(dmslot0, 'rb')
			test.seek(((firstpart-63)*512)+3)
			OEM = test.read(5)
			test.seek(((firstpart-63)*512)+1024)
			HFSPSig = test.read(2)
			test.seek(((firstpart-63)*512)+1080)
			ExtSig = test.read(2)
			test.seek(((firstpart-63)*512)+1097)
			ExtOS = test.read(3)
			test.seek(((firstpart-63)*512)+1120)
			FIARes = test.read(3)
			test.close()
			if ExtSig == binExtSig and ExtOS == bin000000:
				isExt = True
			elif HFSPSig == binHFSJ and FIARes == bin000000:
				isHFSP = True
			elif HFSPSig == binHFSX and FIARes == bin000000:
				isHFSP = True
			if OEM == binMSDOS or OEM == binMSWIN or OEM == binEXFAT or OEM == binNTFS or OEM == binMKDOS or OEM == binIBM or OEM == binFREEDOS or OEM == binMKFS or isExt or isHFSP:
##			if the decryption has worked create a full disk image with the first 63 sectors left as they are (not decrypted), but with all following sectors decrypted
				print('Decrypting ' + args.FILE + ' using' + crypt)
				dmsetupcmd2 = 'dmsetup ' + ro + ' create ' + dmname
				dmcreate = subprocess.Popen(dmsetupcmd2, shell=True, universal_newlines=True, stdin=subprocess.PIPE)
				dmcreate.communicate(input='0 63 linear ' + loopdev + ' 0\n63 ' + str(evsize) + ' linear ' + dmslot0 + ' 0')[0]
				kpartxout = subprocess.check_output(['kpartx', '-l', dmslot], universal_newlines=True)
				noparts = len(kpartxout.split('\n')) - 1
				kparts = kpartxout.split('\n')
				kppparts = ['','','','','','','','','','','','','','','',''] # can handle upto 16 partitions.  Expand this if you need more!
				for k in range(noparts):
					kpparts = kparts[k].split(' ')
					kppparts[k]=kpparts[0]
				kpartxcmd = 'kpartx -a ' + ro + ' ' + dmslot
				subprocess.call(kpartxcmd, shell=True)
				break
##			if it hasn't worked remove device mapping
			else:
				rmdecfile = 'dmsetup remove ' + dmname + '_0'
				subprocess.call(rmdecfile, shell=True)
				if crypt == ' camellia-xts-plain64 ':
					if not isBLKDEV:
						subprocess.call(['losetup', '-d', loopdev])
					print ('Masterkey does not decrypt this disk.  Is the Masterkey correct?')
					exit(1)

##	if a 2 cascaded enryption type
	if len(args.MASTERKEY) == 256:
##		split masterkey into 2
		MK1 = args.MASTERKEY[128:]
		MK2 = args.MASTERKEY[:128]
		crypts = ['aes-twofish', 'serpent-aes', 'twofish-serpent']
		tryhiddenvol = False
##		first check for normal/outer volume
		for crypt in crypts:
			if crypt == 'aes-twofish':
				EN1 = ' aes-xts-plain64 '
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
		crypts = ['aes-twofish-serpent', 'serpent-twofish-aes']
		tryhiddenvol = False
##		first check for normal/outer volume
		for crypt in crypts:
			if crypt == 'aes-twofish-serpent':
				EN1 = ' aes-xts-plain64 '
				EN2 = ' twofish-xts-plain64 '
				EN3 = ' serpent-xts-plain64 '
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
		

##	pause waiting for kpartx to catchup	
	time.sleep(1)
##	if requested, mount the decrypted volume
	if mp:
		for l in range(noparts):
			mntdir = args.mountpoint + '/p' + str(l+1)
			partslot = str('/dev/mapper/' + kppparts[l])
			subprocess.call(['mkdir', mntdir])
			mountcmd = 'mount ' + ro + ' ' + partslot + ' ' + mntdir
			subprocess.call(mountcmd, shell=True)
			print('Partition ' + str(l+1) + ' has been decrypted at ' + partslot + ' and mounted at ' + mntdir)

	else:
		print(args.FILE + ' is decrypted at ' + dmslot)
		for l in range(noparts):
			print('Partition ' + str(l+1) + ' is decrypted at /dev/mapper/' + kppparts[l])


##	pause until user presses enter while also checking that
##	mount and device mapping are no longer being used
	mount=True
	while mount:
		while mount:
			input('Once done, press Enter to dismount ' + args.FILE + '...')
			if mp:
				for p in range(noparts):
					mntdir = args.mountpoint + '/p' + str(l+1)
					partslot = str('/dev/mapper/' + kppparts[l])
					umountcmd = 'umount ' + partslot
					check = subprocess.call(umountcmd, shell=True, stderr=subprocess.DEVNULL)
					if not check == 0:
						print(partslot + " is still in use!")
						break
					elif args.verbose:
						print('Partition ' + str(p+1) + ' unmounted from ' + mntdir)
					subprocess.call(['rmdir', mntdir])
				if not check ==0:
					break
			if len(args.MASTERKEY) >= 128:
				rmkpcmd = 'kpartx -d /dev/mapper/' + dmname
				rmdmcmd1 = 'dmsetup remove ' + dmname
				rmdmcmd2 = 'dmsetup remove ' + dmname + '_0'
				check = subprocess.call(rmkpcmd, shell=True, stderr=subprocess.DEVNULL)	
				if not check == 0:
					print("Device mapping: " + dmslot + " is still in use!")
					break
				else:
					subprocess.call(rmdmcmd1, shell=True, stderr=subprocess.DEVNULL)
					subprocess.call(rmdmcmd2, shell=True, stderr=subprocess.DEVNULL)
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
