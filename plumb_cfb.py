from Crypto.Cipher import AES
from doublecfb import aesDecryptCFBdbl as DecryptCFBdbl
from util import xor_bytes, neg_bytes
import ctypes
import struct

# Monkey-patch in some arithmetic (gross!)
def uint_add(self, other):
    return ctypes.c_uint32(self.value + other.value)
def uint_xor(self, other):
    return ctypes.c_uint32(self.value ^ other.value)
def uint_lshift(self, n):
    return ctypes.c_uint32(self.value << n)
ctypes.c_uint32.__add__ = uint_add
ctypes.c_uint32.__xor__ = uint_xor
ctypes.c_uint32.__lshift__ = uint_lshift

IV_SIZE = 32
SECTOR_SIZE = 512
SECTOR_SIZE_IN_U32 = SECTOR_SIZE // 4

def get_sector(f, block):
    f.seek(block*SECTOR_SIZE)
    return f.read(SECTOR_SIZE)

def SECTOR_LOW_U32(x):
    return ctypes.c_uint32(x.value & 0xffffffff)

def SECTOR_HIGH_U32(x):
    return ctypes.c_uint32(x.value >> 32)

# calculates the checksum based on the whole block,
# except the last cipherblock.
# Cipherblock size is 16 bytes
#
# sum is always in native byte order (i.e. it's an integer).
#
def getSum16(inBlock_bytes, salt_bytes, blockNumber):
    blockNumber = ctypes.c_uint64(blockNumber)
    assert len(inBlock_bytes) == SECTOR_SIZE
    assert len(salt_bytes) == 16
    sumOut = [ctypes.c_uint32(0) for _ in range(4)]
    inBlock = struct.unpack("<" + "I"*SECTOR_SIZE_IN_U32, inBlock_bytes)
    inBlock = [ctypes.c_uint32(x) for x in inBlock]
    salt = struct.unpack("<"+"I"*4, salt_bytes)
    salt = [ctypes.c_uint32(x) for x in salt]

    blockSum = SECTOR_LOW_U32(blockNumber) + SECTOR_HIGH_U32(blockNumber)

    sumOut[0] = salt[0] + blockSum
    sumOut[1] = salt[1] + blockSum
    sumOut[2] = salt[2] + blockSum
    sumOut[3] = salt[3] + (blockSum ^ (SECTOR_HIGH_U32(blockNumber)<<1))
                
    # sum exerything but the last block
    for i in range(SECTOR_SIZE_IN_U32-4):
        sumOut[3] += inBlock[i]
        sumOut[2] += sumOut[3]
        sumOut[1] += sumOut[2]
        sumOut[0] += sumOut[1]
    
    # Convert back
    sumOut = [x.value for x in sumOut]
    return struct.pack("<4I", *sumOut)

# DecryptCFBdbl( iv2, inBlock, outBlock, size, cc )
# aesDecryptCFBdbl(key, plaintext, ivs)

def aesPlumbCFB_Decrypt512(inBlock_bytes, blockNumber, key, salt):
    # decrypt second half of the block using preceeding 
    # bytes as IV_prev 
    iv1 = inBlock_bytes[SECTOR_SIZE//2 - IV_SIZE : SECTOR_SIZE//2]
    second_half = DecryptCFBdbl(key, inBlock_bytes[512//2:], iv1)

    # E(IV_prev) ^ C = E(IV_prev) ^ E(IV_prev) ^ P ^ sum = P ^ sum,
    # so we recovered P ^ sum == IV_0
    # invert half of IV
    iv2 = second_half[-IV_SIZE//2:]
    iv2 += neg_bytes(iv2)

    # now can decrypt first half
    first_half = DecryptCFBdbl(key, inBlock_bytes[:512//2], iv2)
        
    # finally fix the last block:
    # get P from IV_0 == P ^ sum
    sum16 = getSum16(first_half + second_half, salt, blockNumber)
    last_block = xor_bytes(second_half[-16:], sum16)
    return first_half + second_half[:-16] + last_block
