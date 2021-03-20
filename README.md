# wdepy: Decryption and Inspection for PGP WDE Disks

This is a small python tool to inspect and decrypt disk images encrypted with PGP Whole Disk Encryption (including the Symantec-branded versions like Symantec Drive Encryption). It takes advantage of mutliple cores and should be significantly faster (in my case, ~20X, from 30 hours down to 87 minutes) than the [official recovery tool](https://knowledge.broadcom.com/external/article?legacyId=TECH210725).

## Installation

Run `pip install -r requirements.txt` to get the dependencies. No `setup.py` (yet!).

## Usage and Features

Run `python pgpwde.py --help` to get a list of options. You can:

* List whole disk users and check if a password matches any of them
* Dump password hashes in John the Ripper format
* List and extract files from the internal PGP BootGuard Filesystem (BGFS)
* Decrypt a disk image given a username and passphrase 

## Warnings

This has been tested on precisely one disk, and is based on reading the released PGP WDE source code. It is very likely that I've gotten a lot of edge cases wrong, but it works for me. Pull requests are welcome to fix things I got wrong!

If you're looking for a more reliable (but slower) tool to recover a PGP WDE-encrypted disk, have a look at the [official PGP WDE recovery tools](https://knowledge.broadcom.com/external/article?legacyId=TECH210725).
