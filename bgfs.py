#!/usr/bin/env python

import sys
import struct
import binascii 
from hexdump import hexdump
from collections import OrderedDict
from enum import Enum
import copy

def merge_intervals(intervals):
    intervals.sort()
    merged = []
    cur_st, cur_ed = intervals[0] 
    for st,ed in intervals[1:]:
        if cur_ed == st:
            cur_ed = ed
        else:
            merged.append((cur_st, cur_ed))
            cur_st, cur_ed = st, ed
    merged.append((cur_st, cur_ed))
    return merged

def szmask(sz):
    return (1 << sz) - 1

def extract_flags(flagdef, val):
    flags = []
    i = 0
    for k,sz in flagdef:
        if (val >> i) & szmask(sz): flags.append(k)
        i += sz
    return flags

bgfs_flags = [
    ('COMPRESSED', 1),
    ('WRITABLE', 1),
    ('SENSITIVE', 1),
]

bitmap_flags = [
    ("is_boot_partition", 1),
    ("conversion_requested", 1),
    ("is_current_partition", 1),
    ("is_dos_extended_partiton", 1),
    ("is_excluded", 1),
    ("unused", 3),
]

user_flags = [
    ('System', 1),
    ('SSO', 1),
    ('Stub', 1),
    ('Locked', 1),
    ('Admin', 1),
    ('SelfRecover', 1),
]

class StructRecord:
    def __init__(self, fmt, fieldnames):
        self.fmt = fmt
        self.size = struct.calcsize(fmt)
        self.fieldnames = fieldnames
        self.parsed = None
    def parse(self, data):
        assert len(data) == self.size
        self.data = data
        vals = struct.unpack(self.fmt, data)
        assert len(vals) == len(self.fieldnames)
        self.parsed = OrderedDict(zip(self.fieldnames, vals))
        return self.parsed
    def print(self):
        assert self.parsed is not None
        for k,v in self.parsed.items():
            print(f"{k}: {v}")
    def copy(self):
        s = StructRecord(self.fmt, self.fieldnames)
        s.parsed = copy.deepcopy(self.parsed)
        s.data = self.data
        s.size = self.size
        return s
    def __getitem__(self, item):
        assert self.parsed is not None
        return self.parsed[item]

# Power of 10 sizes since we're dealing with disks :p
def sizeof_fmt(num, suffix='B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1000.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1000.0
    return "%.1f%s%s" % (num, 'Y', suffix)

SECTOR_SIZE = 512
BGFS_HEADER_SIZE = 2

# Structure definitions
mbr_fmt = "< 3s I I 51s B B B B Q 366s I H"
MBR = StructRecord(mbr_fmt,
        [ "JumpCode", "MagicCookie", "MagicCookie2", "BPB", "MajorVersion", "MinorVersion",
          "BootDrive", "BGFSBackupSector", "Stage2Sector", "bootCode", "NTMagic", "Unknown" ])
stage2_fmt = "< 480s 8s B B H I Q H H H H"
Stage2 = StructRecord(stage2_fmt,
        [ "reserved", "signature", "major_version", "minor_version", "total_len",
          "signature_reserved", "blocklist_default_start", "blocklist_bgfs_offset",
          "blocklist_stage2_offset", "blocklist_stage2_len", "blocklist_start_marker" ])
assert Stage2.size == SECTOR_SIZE
bgfs_entry_fmt = "< B 8sB H H H H 2s I Q"
BGFSEntry = StructRecord(bgfs_entry_fmt,
        [ "MajorVersion", "FileName", "Attributes", "FileLen", "MaxLen", "SectorNumber",
          "MinorVersion", "Reserved", "CRC32", "Sig" ])

# WDE_STATUS_BLOCK
wde_status_fmt = "< I H B B I I B B B B B B B B I I B B B 3s B B Q"
WDEStatus = StructRecord(wde_status_fmt,
        [ "magic", "length", "majorversion", "minorversion", "keyindexinverse",
          "keyvaliditymask", "keyreference1", "keyreference2",
          "instrumentpartition", "numextendedpartitions", "scheme",
          "numpendingpartitions", "diskstatus", "interrupted",
          "partitionencryptionrequestbitmap", "partitionencryptedbitmap",
          "blocksize", "flags", "crctblinuse", "padding_3", "langID", "keybID",
          "totalsectors" ])
wde_bitmap_fmt = "< Q Q Q Q Q H B B I"
WDEBitmap = StructRecord(wde_bitmap_fmt,
        [ "lowwatermark", "watermark", "watermark_old", "startingsector",
            "totalsectors", "reservedstartsectors", "reserved", "flags",
            "reservedendsectors" ])

# User records
pgpDiskOnDiskUserInfoHeader_fmt = "< H B B I B B 2s"
pgpDiskOnDiskUserInfoHeader = StructRecord(pgpDiskOnDiskUserInfoHeader_fmt,
        [ "size", "version", "type", "magic", "totalRecords", "currentRecord",
          "reserved" ])
pgpDiskOnDiskUserInfoPrimary_fmt = "< H I H 6s"
pgpDiskOnDiskUserInfoPrimary = StructRecord(pgpDiskOnDiskUserInfoPrimary_fmt,
        [ "userflags", "serialNumber", "userLocalId", "reserved" ])
pgpDiskOnDiskUserInfoSecondary_fmt = "< I 384s"
pgpDiskOnDiskUserInfoSecondary = StructRecord(pgpDiskOnDiskUserInfoSecondary_fmt,
        [ "reserved", "eskChunk" ])
pgpDiskOnDiskUserWithSym_fmt = "< H B H 3s 128s B I 3s 16s 128s"
pgpDiskOnDiskUserWithSym = StructRecord(pgpDiskOnDiskUserWithSym_fmt,
        [ "size", "symmAlg", "totalESKsize", "reserved", "userName", "s2ktype",
          "hashIterations", "reserved2", "salt", "esk" ])
pgpDiskOnDiskLinkKey_fmt = "< H B H 3s 128s 128s 16s 16s B 3s"
pgpDiskOnDiskLinkKey = StructRecord(pgpDiskOnDiskLinkKey_fmt,
        [ "size", "symmAlg", "totalESKsize", "reserved", "esk", "anonymousESK",
          "uuid", "offloadUuid", "offloadStatus", "reserved_alt" ])
pgpDiskOnDiskSessionKeys_fmt = "< H B H 3s 128s 16s B I B B B 16s 16s 16s 128s 128s"
pgpDiskOnDiskSessionKeys = StructRecord(pgpDiskOnDiskSessionKeys_fmt,
        [ "size", "symmAlg", "totalESKsize", "reserved", "diskID", "uuid",
          "s2ktype", "hashIterations", "diskBlockMode", "diskBlockModeOld",
          "reserved2", "salt", "diskSalt", "diskSaltOld", "esk", "eskOld" ])
pgpDiskOnDiskUserWithTokenPub_fmt = "< H B H H B I 128s I 8s 256s"
pgpDiskOnDiskUserWithTokenPub = StructRecord(pgpDiskOnDiskUserWithTokenPub_fmt,
        [ "size", "pubAlg", "totalESKsize", "pubFlags", "reserved", "tokenID",
          "userName", "tokenKeyID", "keyID", "esk" ])
pgpDiskOnDiskUserWithPub_fmt = "< H B H H B 128s 8s 256s"
pgpDiskOnDiskUserWithPub = StructRecord(pgpDiskOnDiskUserWithPub_fmt,
        [ "size", "pubAlg", "totalESKsize", "pubFlags", "reserved", "userName",
          "keyID", "esk" ])
pgpDiskOnDiskUserWithTpm_fmt = "< H H 4s 128s 256s"
pgpDiskOnDiskUserWithTpm = StructRecord(pgpDiskOnDiskUserWithTpm_fmt,
        [ "size", "totalESKsize", "reserved", "userName", "esk" ])

class WDEUserType(Enum):
    UnknownKeysType           = 0
    PseudoUserSessionKeysType = 0x01
    PseudoUserLinkKeyType     = 0x02
    UserWithSymType           = 0x08
    UserWithTokenPubType      = 0x09
    UserWithPubType           = 0x0A
    UserWithTpmType           = 0x0B

userTypeClass = {
    WDEUserType.PseudoUserSessionKeysType: pgpDiskOnDiskSessionKeys,
    WDEUserType.PseudoUserLinkKeyType: pgpDiskOnDiskLinkKey,
    WDEUserType.UserWithSymType: pgpDiskOnDiskUserWithSym,
    WDEUserType.UserWithTokenPubType: pgpDiskOnDiskUserWithTokenPub,
    WDEUserType.UserWithPubType: pgpDiskOnDiskUserWithPub,
    WDEUserType.UserWithTpmType: pgpDiskOnDiskUserWithTpm,
}

class PGPCipherAlgorithm(Enum):
    NONE        = 0
    IDEA        = 1
    TRIPLE_DES  = 2
    CAST5       = 3
    Blowfish    = 4  
    AES128      = 7
    AES192      = 8
    AES256      = 9
    Twofish256  = 10
    
class PGPHashAlgorithm(Enum):
    Invalid       = 0
    MD5           = 1
    SHA           = 2
    RIPEMD160     = 3
    SHA256        = 8
    SHA384        = 9
    SHA512        = 10

class PGPPublicKeyAlgorithm(Enum):
    Invalid          = -1
    RSA              = 1
    RSAEncryptOnly   = 2
    RSASignOnly      = 3
    ElGamal          = 0x10
    DSA              = 0x11
    ECEncrypt        = 0x12
    ECSign           = 0x13

class WDEUsers:
    def __init__(self, userdata_block):
        #hexdump(userdata_block)
        self.userdata_block = userdata_block
        self.users = OrderedDict()
        # Walk through the data block. Each chunk is one sector
        for i in range(0,len(userdata_block),SECTOR_SIZE):
            data = userdata_block[i:i+SECTOR_SIZE]
            # Header
            pgpDiskOnDiskUserInfoHeader.parse(data[:pgpDiskOnDiskUserInfoHeader.size])
            data = data[pgpDiskOnDiskUserInfoHeader.size:]

            if pgpDiskOnDiskUserInfoHeader['currentRecord'] == 0:
                # Header for primary records
                pgpDiskOnDiskUserInfoPrimary.parse(data[:pgpDiskOnDiskUserInfoPrimary.size])
                data = data[pgpDiskOnDiskUserInfoPrimary.size:]

                # Check for each type of user. Each goes into its own key.
                kind = pgpDiskOnDiskUserInfoHeader['type']
                if WDEUserType(kind) == WDEUserType.PseudoUserSessionKeysType:
                    self.users['sessionKeys'] = {}
                    pgpDiskOnDiskSessionKeys.parse(data[:pgpDiskOnDiskSessionKeys.size])
                    self.users['sessionKeys']['struct'] = pgpDiskOnDiskSessionKeys.copy()
                    self.users['sessionKeys']['header'] = pgpDiskOnDiskUserInfoHeader.copy()
                    self.users['sessionKeys']['primary'] = pgpDiskOnDiskUserInfoPrimary.copy()
                elif WDEUserType(kind) == WDEUserType.PseudoUserLinkKeyType:
                    self.users['linkKey'] = {}
                    pgpDiskOnDiskLinkKey.parse(data[:pgpDiskOnDiskLinkKey.size])
                    self.users['linkKey']['struct'] = pgpDiskOnDiskLinkKey.copy()
                    self.users['linkKey']['header'] = pgpDiskOnDiskUserInfoHeader.copy()
                    self.users['linkKey']['primary'] = pgpDiskOnDiskUserInfoPrimary.copy()
                elif (   WDEUserType(kind) == WDEUserType.UserWithSymType
                      or WDEUserType(kind) == WDEUserType.UserWithTokenPubType
                      or WDEUserType(kind) == WDEUserType.UserWithPubType
                      or WDEUserType(kind) == WDEUserType.UserWithTpmType):
                    # All of these are the same for our purposes -- they have a userName field
                    # Slightly magical but avoids code duplication
                    userClass = userTypeClass[WDEUserType(kind)]
                    userClass.parse(data[:userClass.size])
                    username = WDEUsers.format_username(userClass['userName'])
                    self.users[username] = {}
                    self.users[username]['struct'] = userClass.copy()
                    self.users[username]['header'] = pgpDiskOnDiskUserInfoHeader.copy()
                    self.users[username]['primary'] = pgpDiskOnDiskUserInfoPrimary.copy()
                elif WDEUserType(kind) == WDEUserType.UnknownKeysType:
                    continue
                else:
                    raise ValueError(f"Unknown user type {kind}")

            if pgpDiskOnDiskUserInfoHeader['currentRecord'] > 0:
                # Warning: untested code! Haven't seen any of these in the wild.
                raise NotImplementedError()
                pgpDiskOnDiskUserInfoSecondary.parse(data[:pgpDiskOnDiskUserInfoSecondary.size])
                # In theory you would then tack this data on to the previous user record.
                # My guess is that this is for public key users with large key sizes.
                # You'd want eskChunk from this record.

    def format_username(s):
        parts = s.split(b'\x00')
        # SSO users have username and then domain separated by NULs
        # There's also a byte at the end that maybe is the user type? Can't find
        # any documentation for that in the source code, though.
        parts = [p for p in parts if p]
        if len(parts) > 2:
            return f"{parts[1].decode('utf8')}\\{parts[0].decode('utf8')}"
        else:
            return parts[0].decode('utf8')

    def __getitem__(self, item):
        return self.users[item]

    def __iter__(self):
        return iter(self.users)

class BGFS:
    def __init__(self, f, bgfs_start):
        self.bgfs = OrderedDict() 
        self.bgfs_start = bgfs_start
        f.seek(bgfs_start*SECTOR_SIZE)
        bgfs_header = f.read(BGFS_HEADER_SIZE*SECTOR_SIZE)
        for i in range(0, BGFS_HEADER_SIZE*SECTOR_SIZE, BGFSEntry.size):
            BGFSEntry.parse(bgfs_header[i:i+BGFSEntry.size])
            fn_strip = BGFSEntry['FileName'].strip(b'\00').decode('utf8')
            if fn_strip == '': continue
            self.bgfs[fn_strip] = {'fields': BGFSEntry.parsed}
            f.seek((bgfs_start + BGFSEntry['SectorNumber'])*SECTOR_SIZE)
            file_data = f.read(BGFSEntry['MaxLen']*SECTOR_SIZE)
            self.bgfs[fn_strip]['data'] = file_data
            self.bgfs[fn_strip]['struct'] = BGFSEntry.copy()

    def print(self):
        for i,k in enumerate(self.bgfs):
            print(f"===== BGFS Entry [{i}] =====")
            self.bgfs[k]['struct'].print()

    def __getitem__(self, k):
        return self.bgfs[k]

    def __iter__(self):
        return iter(self.bgfs)

    def sectors(self):
        intervals = []
        for k in self.bgfs:
            entry = self.bgfs[k]['struct']
            intervals.append((
                entry['SectorNumber'] + self.bgfs_start,
                entry['SectorNumber'] + self.bgfs_start + entry['MaxLen'],
            ))
        return merge_intervals(intervals)
    
class WDEDisk:
    def __init__(self, f):
        f.seek(0) # MBR is first sector
        mbr_data = f.read(MBR.size)
        MBR.parse(mbr_data)
        self.MBR = MBR
        if not (    self.MBR['MagicCookie']  == 0x47504750   # PGPG
                and self.MBR['MagicCookie2'] == 0x44524155): # UARD
            raise ValueError("Not a PGP WDE Disk (no magic)")

        # Read the Primary BGFS
        f.seek(MBR['Stage2Sector']*SECTOR_SIZE)
        stage2_data = f.read(SECTOR_SIZE)
        Stage2.parse(stage2_data)
        crc16 = binascii.crc32(stage2_data[:-2] + b'\0\0') & 0xffff
        assert Stage2['blocklist_start_marker'] == crc16
        self.primary_stage2 = Stage2.copy()
        primary_bgfs_start = Stage2['blocklist_default_start'] + Stage2['blocklist_bgfs_offset']
        self.primary_bgfs = BGFS(f,primary_bgfs_start)

        # Read the Backup BGFS
        f.seek(MBR['BGFSBackupSector']*SECTOR_SIZE)
        stage2_data = f.read(SECTOR_SIZE)
        Stage2.parse(stage2_data)
        crc16 = binascii.crc32(stage2_data[:-2] + b'\0\0') & 0xffff
        assert Stage2['blocklist_start_marker'] == crc16
        self.backup_stage2 = Stage2.copy()
        backup_bgfs_start = Stage2['blocklist_default_start'] + Stage2['blocklist_bgfs_offset']
        self.backup_bgfs = BGFS(f,backup_bgfs_start)

        # Get some specific BGFS entries that are useful: usrrec and wdestatus
        
        # Bitmap data from the WDE Status Block
        status_data = self.backup_bgfs['wdestat']['data']
        WDEStatus.parse(status_data[:WDEStatus.size])
        self.WDEStatus = WDEStatus.copy()
        self.WDEBitmaps = []
        bitmap_data = status_data[WDEStatus.size:]
        for i in range(0, 6*WDEBitmap.size, WDEBitmap.size):
            WDEBitmap.parse(bitmap_data[i:i+WDEBitmap.size])
            self.WDEBitmaps.append(WDEBitmap.copy())

        # User records
        self.users = WDEUsers(self.primary_bgfs['usrrec']['data'])
        self.backup_users = WDEUsers(self.backup_bgfs['usrrec']['data'])

    def sectors(self):
        intervals = []
        # MBR
        intervals.append((0,1))
        # Stage2 Primary
        intervals.append((self.MBR['Stage2Sector'], self.MBR['Stage2Sector']+1))
        # Stage2 Backup
        intervals.append((self.MBR['BGFSBackupSector'], self.MBR['BGFSBackupSector']+1))
        # BGFS Primary
        intervals += self.primary_bgfs.sectors()
        # BGFS Backup
        intervals += self.backup_bgfs.sectors()
        return merge_intervals(intervals)

if __name__ == "__main__":
    f = open(sys.argv[1],'rb')
    disk = WDEDisk(f)
    print("===== MBR =====")
    disk.MBR.print()
    print("===== STAGE 2 (Primary) =====")
    disk.primary_stage2.print()
    disk.primary_bgfs.print()
    print("===== STAGE 2 (Backup) =====")
    disk.backup_stage2.print()
    disk.backup_bgfs.print()
    print("===== WDE STATUS BLOCK =====")
    disk.WDEStatus.print()
    print(f"Size: {sizeof_fmt(disk.WDEStatus['totalsectors']*SECTOR_SIZE)}")

    for i,bitmap in enumerate(disk.WDEBitmaps):
        print(f"===== BITMAP [{i}] =====")
        bitmap.print()
        print(f"flags: {extract_flags(bitmap_flags,bitmap['flags'])}")        

    for user in disk.users:
        print(f"===== USER {user} =====")
        user_struct = disk.users[user]['struct']
        primary = disk.users[user]['primary']
        header = disk.users[user]['header']
        user_struct.print()
        print(f"UserFlags: {extract_flags(user_flags,primary['userflags'])}")
        kind = header['type']
        if WDEUserType(kind) == WDEUserType.UserWithSymType:
            print(f"Symmetric Alg: {PGPCipherAlgorithm(user_struct['symmAlg'])}")
        elif WDEUserType(kind) in (WDEUserType.UserWithTokenPubType, WDEUserType.UserWithPubType):
            print(f"PubKey Alg: {PGPPublicKeyAlgorithm(user_struct['pubAlg'])}")

    print("PGP WDE Intervals:")
    print(disk.sectors())

    assert disk.primary_bgfs['oldboot']['data'] == disk.backup_bgfs['oldboot']['data']
