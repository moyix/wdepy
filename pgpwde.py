#!/usr/bin/env python

from tabulate import tabulate
from bgfs import (WDEDisk, WDEUserType, PGPCipherAlgorithm, PGPPublicKeyAlgorithm,
                  extract_flags, user_flags, bgfs_flags)
from oaep_unpad import keyTypeStr
from wde_crypt import decrypt_with_passphrase, decrypt_symmetric
from plumb_cfb import aesPlumbCFB_Decrypt512
from intervaltree import IntervalTree
from hexdump import hexdump
import multiprocessing
import itertools
import argparse
import sys
import os
import time

SECTOR_SIZE = 512

# Why doesn't python have this??
def open_rdwr(filename):
    f = os.fdopen(os.open(filename, os.O_RDWR | os.O_CREAT), 'rb+')
    return f

def listusers(args):
    with open(args.disk_image,'rb') as f:
        disk = WDEDisk(f)
        rows = []
        users = disk.backup_users if args.backup else disk.users
        for user in users:
            if user in ('linkKey', 'sessionKeys'): continue
            user_st = users[user]['struct']
            header = users[user]['header']
            primary = users[user]['primary']
            kind = WDEUserType(header['type'])
            if kind == WDEUserType.UserWithSymType:
                alg = PGPCipherAlgorithm(user_st['symmAlg'])
            elif kind in (WDEUserType.UserWithTokenPubType, WDEUserType.UserWithPubType):
                alg = PGPPublicKeyAlgorithm(user_st['pubAlg'])
            flags = ",".join(extract_flags(user_flags,primary['userflags']))
            row = [user, kind.name, alg.name, flags]
            if args.passphrase:
                if kind == WDEUserType.UserWithSymType:
                    iterations = user_st['hashIterations']
                    iterations = 1 << 17 if iterations == 0 else 1 << iterations
                    try:
                        decrypt_with_passphrase(
                                user_st['esk'],
                                args.passphrase,
                                user_st['salt'],
                                iterations,
                                kind.value
                        )
                        row.append('True')
                    except ValueError:
                        row.append('False')
                else:
                    # Don't know how to validate public key users
                    row.append('False')
            rows.append(row)

        headers = ['Username','User Type', 'Algorithm', 'Flags']
        if args.passphrase: headers.append('Passphrase Match?')
        print(tabulate(rows, headers=headers))

def userhash(args):
    with open(args.disk_image,'rb') as f:
        disk = WDEDisk(f)
        users = disk.backup_users if args.backup else disk.users
        for user in users:
            if user in ('linkKey', 'sessionKeys'): continue
            user_st = users[user]['struct']
            header = users[user]['header']
            primary = users[user]['primary']
            kind = WDEUserType(header['type'])
            if kind == WDEUserType.UserWithSymType:
                print("%s:$pgpwde$0*%s*%s*%s*%s*%s" % (user, user_st['symmAlg'], user_st['s2ktype'],
                                                       user_st['hashIterations'],
                                                       user_st['salt'].hex(),
                                                       user_st['esk'].hex()))

def decrypt_task(args):
    filename, output, key, salt, sector_range = args
    with open(filename, 'rb') as f, open_rdwr(output) as out:
        for sector in sector_range:
            f.seek(sector*SECTOR_SIZE)
            block = f.read(SECTOR_SIZE)
            decrypted = aesPlumbCFB_Decrypt512(block, sector, key, salt)
            out.seek(sector*SECTOR_SIZE)
            out.write(decrypted)

def decryptdisk(args):
    with open(args.disk_image,'rb') as f:
        disk = WDEDisk(f)
        user = disk.users[args.username]
        user_st = user['struct']
        header = user['header']
        primary = user['primary']
        kind = WDEUserType(header['type'])
        if kind != WDEUserType.UserWithSymType:
            print("Sorry, only symmetric passphrase users supported...", file=sys.stderr)
            sys.exit(1)

        # Get the DAK/PEK
        iterations = user_st['hashIterations']
        iterations = 1 << 17 if iterations == 0 else 1 << iterations
        user_key = decrypt_with_passphrase(
            user_st['esk'],
            args.passphrase,
            user_st['salt'],
            iterations,
            kind.value
        )
        assert keyTypeStr[user_key[0]]  == 'PGP_WDE_DAK_ID'
        assert keyTypeStr[user_key[33]] == 'PGP_WDE_PEK_ID'
        dak = user_key[1:33]

        # Get the link key
        link = disk.users['linkKey']['struct']
        link_key = decrypt_symmetric(link['esk'], dak, WDEUserType.PseudoUserLinkKeyType.value)
        assert keyTypeStr[link_key[0]] == 'PGP_WDE_LINK_KEY_ID'
        link_key = link_key[1:]

        # Finally get the session keys
        session = disk.users['sessionKeys']['struct']
        session_key = decrypt_symmetric(session['esk'], link_key, WDEUserType.PseudoUserSessionKeysType.value)
        disk_salt = session['diskSalt']
        session_key_old = decrypt_symmetric(session['eskOld'], link_key, WDEUserType.PseudoUserSessionKeysType.value)
        disk_salt_old = session['diskSaltOld']
        assert keyTypeStr[session_key[0]] == 'AES_256'
        assert keyTypeStr[session_key_old[0]] == 'AES_256'
        session_key = session_key[1:]
        session_key_old = session_key_old[1:]
        keys = [
            (session_key, disk_salt),
            (session_key_old, disk_salt_old),
        ]

        # Figure out what parts of the disk are actually encrypted, and with what keys
        # Some caveats:
        #   1) We only support the whole-disk mode. PGP WDE also supports
        #      a partition-based mode, but we don't try to deal with that.
        #      We detect this by looking at the scheme flag in the status
        #      block and aborting if it's not whole-disk mode.
        #   2) PGP WDE disks can be in weird transitional states during key
        #      updates, where half the disk is encrypted with the new key
        #      and half is encrypted with the old key. To handle this the
        #      status block includes a "watermark", which represents the
        #      dividing line between data encrypted with the old key and
        #      the new key. We attempt to handle this, but the disk I have
        #      is all encrypted with one key, so I can't test it properly.
        #   3) According to clients2/wde/shared/wdestat.h, there's an extra
        #      feature where the bits of keyvaliditymask determine whether a
        #      section is encrypted:
        #      if ( !(keyvaliditymask & 1) ) 
        #          then [0,watermark] is not encrypted
        #      if ( !(keyvaliditymask & 2) ) 
        #          then [watermark_old,totalsectors-1] is not encrypted
        #      Not going to bother trying to handle this.
        status = disk.WDEStatus
        scheme = status['scheme'] & 0xf
        if scheme not in (0,2):
            print("Disk is encrypted with the partition-mode scheme,"
                  "which is unsupported. Aborting!", file=sys.stdout)
            sys.exit(1)
        # I *think* we only care about the first bitmap in whole-disk mode
        bitmap = disk.WDEBitmaps[0]
        # relative to bitmap.startsector+bitmap.reservedstartsectors:
        # 0 - watermark                : key index 0
        # watermark - watermark_old    : key index 1
        # watermark_old - totalsectors : unencrypted
        start = bitmap['startingsector'] + bitmap['reservedstartsectors']
        watermark = start + bitmap['watermark']
        if bitmap['watermark_old'] != 0:
            watermark_old = bitmap['watermark_old']
        else:
            watermark_old = watermark
        end = start + bitmap['totalsectors']
        # key index is modified by status.keyindexinverse, which flips
        # which key is used in the first two sections
        if status['keyindexinverse']: # Swap the keys
            keys = [keys[1],keys[0]]
    
        # Last piece. The WDE metadata blocks (MBR, Stage2, and BGFS) should
        # not be decrypted. Remove them here.
        metadata_sectors = IntervalTree.from_tuples(disk.sectors())
        #print(f"Excluding {sum(i.length() for i in metadata_sectors)} WDE metadata sectors")
        key0_blocks = IntervalTree.from_tuples([(start,watermark)]) if watermark-start else IntervalTree()
        key1_blocks = IntervalTree.from_tuples([(watermark,watermark_old)]) if watermark_old-watermark else IntervalTree()
        unencrypted = IntervalTree.from_tuples([(watermark_old,end)])
        for i in metadata_sectors: key0_blocks.chop(i.begin,i.end)
        for i in metadata_sectors: key1_blocks.chop(i.begin,i.end)

        # Gather a list of all non-WDE blocks so we can copy them at the end
        total_sectors = os.path.getsize(args.disk_image) // SECTOR_SIZE
        all_blocks = IntervalTree.from_tuples([(0,total_sectors)])
        for i in metadata_sectors: all_blocks.chop(i.begin,i.end)
        for i in key0_blocks: all_blocks.chop(i.begin,i.end)
        for i in key1_blocks: all_blocks.chop(i.begin,i.end)
        for i in unencrypted: all_blocks.chop(i.begin,i.end)

        #print("Key 0 blocks:",key0_blocks)
        #print("Key 1 blocks:",key1_blocks)
        #print("Unencrypted blocks:",unencrypted)

        # Build our iterables
        key0, salt0 = keys[0]
        key1, salt1 = keys[0]
        # filename, output, key, salt, blockNum 
        all_work_size = sum(i.length() for i in key0_blocks) + sum(i.length() for i in key1_blocks)
        chunk_size = all_work_size // multiprocessing.cpu_count()
        chunks = []
        for i in key0_blocks:
            for j in range(i.begin,i.end,chunk_size):
                st,ed = j,min(j+chunk_size,i.end)
                chunks.append( (args.disk_image, args.output, key0, salt0, range(st,ed)) )
        for i in key1_blocks:
            for j in range(i.begin,i.end,chunk_size):
                st,ed = j,min(j+chunk_size,i.end)
                chunks.append( (args.disk_image, args.output, key1, salt1, range(st,ed)) )

        print("Everything looks good, starting decryption")
        
        # Decrypt in subprocesses. decrypt_task doesn't return anything so just
        # wrap it in a list to consume the iterator and block
        with multiprocessing.Pool() as pool:
            list(pool.imap(decrypt_task, chunks))

        # Copy over the old boot sector and any unencrypted sectors
        with open(args.disk_image, 'rb') as f, open_rdwr(args.output) as out:
            # Old boot sector
            print("Restoring old boot sector...")
            old_mbr = disk.primary_bgfs['oldboot']['data']
            out.seek(0)
            out.write(old_mbr)

            # Unencrypted blocks
            for i in unencrypted:
                for sector in range(i.begin,i.end):
                    f.seek(sector*SECTOR_SIZE)
                    data = f.read(SECTOR_SIZE)
                    out.seek(sector*SECTOR_SIZE)
                    out.write(data)

            # Remaining blocks
            for i in all_blocks:
                for sector in range(i.begin,i.end):
                    f.seek(sector*SECTOR_SIZE)
                    data = f.read(SECTOR_SIZE)
                    out.seek(sector*SECTOR_SIZE)
                    out.write(data)
        print("All done.")

def listbgfs(args):
    with open(args.disk_image,'rb') as f:
        disk = WDEDisk(f)
        if args.backup:
            bgfs = disk.backup_bgfs
        else:
            bgfs = disk.primary_bgfs
        
        if args.file:
            hexdump(bgfs[args.file]['data'])
            return
        
        headers = [ "FileName", "Attributes", "Size (B)", "SectorNumber", "CRC32"]
        rows = []
        for filename in bgfs:
            s = bgfs[filename]['struct']
            rows.append([filename, ','.join(extract_flags(bgfs_flags,s['Attributes'])),
                         s['MaxLen']*SECTOR_SIZE, s['SectorNumber']+bgfs.bgfs_start, hex(s['CRC32']) ])
        print(tabulate(rows, headers=headers))

parser = argparse.ArgumentParser("pgpwde")
subparsers = parser.add_subparsers(title="actions", dest="subparser_name")
listusers_cmd = subparsers.add_parser("listusers", help="list users available")
listusers_cmd.add_argument('-p', '--passphrase', help='passphrase to test')
listusers_cmd.add_argument('-b', '--backup', action='store_true', help='read users from backup BGFS')
decryptdisk_cmd = subparsers.add_parser("decryptdisk", help="decrypt an image")
decryptdisk_cmd.add_argument('-u', '--username', help='username to decrypt', required=True)
decryptdisk_cmd.add_argument('-p', '--passphrase', help='passphrase to decrypt', required=True)
decryptdisk_cmd.add_argument('-o', '--output', help='filename for output', required=True)
listbgfs_cmd = subparsers.add_parser("listbgfs", help="list BootGuardFS (BGFS) filesystem data")
listbgfs_cmd.add_argument('-b', '--backup', action='store_true', help='list the backup BGFS')
listbgfs_cmd.add_argument('-f', '--file', help='dump the content of a BGFS file')
userhash_cmd = subparsers.add_parser("userhash", help="print password hashes in John the Ripper format")
userhash_cmd.add_argument('-b', '--backup', action='store_true', help='read users from backup BGFS')
# All commands need this
parser.add_argument('disk_image', help='disk image to work on')
args = parser.parse_args()

if args.subparser_name == 'listusers':
    listusers(args)
elif args.subparser_name == 'decryptdisk':
    decryptdisk(args)
elif args.subparser_name == 'listbgfs':
    listbgfs(args)
elif args.subparser_name == 'userhash':
    userhash(args)
