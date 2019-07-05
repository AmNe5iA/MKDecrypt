# MKDecrypt(.py)


Usage:
```
MKDecrypt.py [-h] [-v] [-X] [-r | -w] [-m MOUNTPOINT] FILE MASTERKEY
```
MKDecrypt.py (Master Key Decryptor) is a python script to assist with
decrypting encrypted volumes using the recovered masterkey for various
truecrypt type encrypted containers. Script should be run as root,
sudo recommended.

positional arguments:
+  FILE                  the encrypted container, FILE
+  MASTERKEY             the MASTERKEY as a hexadecimal string or file (-X)

optional arguments:
 + -h, --help            show the help message and exits
 + -v, --verbose         verbose output
 + -X, --volatility      specifies MASTERKEY is a volatility file instead of hex chars
 + -r, --read-only       opens FILE in read only mode (default)
 + -w, --read-write      opens FILE in read/write mode
 + -m MOUNTPOINT, --mountpoint MOUNTPOINT
                        mount encrypted volume at MOUNTPOINT

Examples:
```
[sudo] ./MKDecrypt.py -m /mnt truecrypt.tc 123...def
[sudo] ./MKDecrypt.py -v /dev/sdb 123...def
```

Wiki: https://github.com/AmNe5iA/MKDecrypt/wiki

Important:

Veracrypt now supports 2 new encryption algorithms: Camellia and
Kuznyechik. It has also added 5 new cascades: Camellia-Kuznyechik,
Camellia-Serpent, Kuznyechik-AES, Kuznyechik-Serpent-Camellia and
Kuznyechik-Twofish

Kuznyechik encryption requires a linux kernel module found here: 
https://github.com/kuzcrypt/kuznyechik-kernel

Installation instructions:
```
sudo apt update
sudo apt install git build-essential dkms
git clone https://github.com/kuzcrypt/kuznyechik-kernel.git
cd kuznyechik-kernel
sudo make install
```

To install on Windows 10 WSL2:

https://github.com/AmNe5iA/MKDecrypt/wiki/Installing-the-Kuznyechik-kernel-module-on-Windows-Subsystem-for-Linux-version-2-(WSL2)

Other requirements:  Linux OS with Python3.x and LVM2 (dmsetup).
It is preferable to make the script executable before use.

Limitations:

May produce false negatives if the filesystem used is not
one of the standard truecrypt/veracrypt formats.  It is designed to
work with standard truecrypt containers and not bootable
pre-authentication bootloader partitions/disks.  The HFS+
implementation is _sketchy_ but appears to work, for now.

Send BitCoins to: 1AmNe5iAYfYCGYFq7vpLWL4XRFxe21hh9D
