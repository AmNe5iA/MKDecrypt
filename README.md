# MKDecrypt(.py)


usage: MKDecrypt.py [-h] [-v] [-r | -w] [-m MOUNTPOINT] FILE MASTERKEY

MKDecrypt.py (Master Key Decryptor) is a python script to assist with
decrypting encrypted volumes using the recovered masterkey for various
truecrypt type encrypted containers. Script should be run as root,
sudo recommended.

positional arguments:
  FILE                  the encrypted container, FILE
  MASTERKEY             the MASTERKEY as a hexadecimal string

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose output
  -r, --read-only       opens FILE in read only mode (default)
  -w, --read-write      opens FILE in read/write mode
  -m MOUNTPOINT, --mountpoint MOUNTPOINT
                        mount encrypted volume at MOUNTPOINT

Examples: [sudo] ./MKDecrypt.py -m /mnt truecrypt.tc 123...def
          [sudo] ./MKDecrypt.py -v /dev/sdb 123...def


Limitations: May produce false negatives if the filesystem used is not
one of the standard truecrypt/veracrypt formats.  The HFS+
implementation is _sketchy_ but appears to work, for now.
2016-09-16 - Veracrypt now supports 3 new encryption algorithms:
Camellia, Magma (GOST89) and Kuznyechik.  These are only implemented in
non-cascaded modes.  Only Camellia is currently supported by MKDecrypt.

Requirements:  Linux OS with Python3.x and LVM2 (dmsetup).  It is
preferable to make the script executable before use.
