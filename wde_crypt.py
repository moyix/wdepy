import hashlib
from oaep_unpad import oaep_unpad, keyTypeStr
from Crypto.Cipher import AES

SHA_DIGEST_LENGTH = 20

def S2KPGPWDE(password, salt, key_length, iters):
    assert len(salt) == 16
    password = password.encode('utf8')
    num = (key_length - 1) // SHA_DIGEST_LENGTH + 1

    b = b'\0'
    cbytes = iters

    slen = len(password)
    if cbytes < slen + 16:
        cbytes = slen + 16
        
    key = b''
    for i in range(num):
        num_bytes = cbytes
        ctx = hashlib.sha1()
        for j in range(i):
            ctx.update(b)
            
        while num_bytes > slen + 16:
            ctx.update(salt)
            ctx.update(password)
            num_bytes -= slen + 16
        if num_bytes <= 16:
            ctx.update(salt[:num_bytes])
        else:
            ctx.update(salt)
            ctx.update(password[:num_bytes-16])
        key += ctx.digest()

    return key

def decrypt_symmetric(data, key, kind):
    iv = [0]*16
    iv[0] = kind
    iv = bytes(iv)
    ciph = AES.new(key[:32], AES.MODE_CBC, iv=iv)
    dec_data = ciph.decrypt(data)
    return oaep_unpad(dec_data)

def decrypt_with_passphrase(data, password, salt, iterations, kind):
    key = S2KPGPWDE(password, salt, 32, iterations)
    return decrypt_symmetric(data, key, kind)
