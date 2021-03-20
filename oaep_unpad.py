import hashlib
import struct
from util import xor_bytes

PGP_CIPHER_MAX_KEY_BYTES = 32

SHA1_LEN = hashlib.sha1().digest_size
keyTypeStr = {
    255: "PGP_WDE_DAK_ID",
    254: "PGP_WDE_LINK_KEY_ID",
    253: "PGP_WDE_PEK_ID",
    252: "PGP_WDE_MULTISTRING_ID",
    251: "PGP_WDE_STRING_ID",
    # From OpenPGP
    7: "AES_128",
    8: "AES_192",
    9: "AES_256",
}

def i2osp(i):
    return struct.pack(">I", i)

def mgf1(input_str: str, length: int, hash=hashlib.sha1) -> str:
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter)
        output += hash(input_str + C).digest()
        counter += 1
    return output[:length]

def unmask(seed,msg):
    mask = mgf1(seed, len(msg))
    return xor_bytes(mask, msg)

def oaep_unpad(msg):
    # First byte is always 0 and discarded
    if msg[0] != 0: raise ValueError("Padding error")
    msg = msg[1:]

    # Original seed needs to be unmasked first
    orig_seed = unmask(msg[SHA1_LEN:], msg[:SHA1_LEN])

    # Then use that seed to unmask the remainder
    unmasked = unmask(orig_seed, msg[SHA1_LEN:])

    # Unmasked data starts with hash(p). In our case p is ""
    p = b""
    if unmasked[:SHA1_LEN] != hashlib.sha1(p).digest():
        raise ValueError("Padding error")
    unmasked = unmasked[SHA1_LEN:]

    # Finally, we have a bunch of 00s followed by 01, followed by the message
    msgstart = unmasked.find(b'\x01') + 1
    real_msg = unmasked[msgstart:]

    return real_msg
