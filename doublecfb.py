from Crypto.Cipher import AES

def aesEncryptCFBdbl(key, plaintext, iv):
    ivs = [iv[:16], iv[16:]]
    ciph1 = AES.new(key, AES.MODE_CFB, iv=ivs[0], segment_size=128)
    ciph2 = AES.new(key, AES.MODE_CFB, iv=ivs[1], segment_size=128)
    plaintext1 = b''.join(plaintext[i:i+16] for i in range(0,len(plaintext),32))
    plaintext2 = b''.join(plaintext[i:i+16] for i in range(16,len(plaintext),32))
    ciphertext1 = ciph1.encrypt(plaintext1)
    ciphertext2 = ciph2.encrypt(plaintext2)
    ciphertext = b''.join( a + b for a,b in zip(
        (ciphertext1[i:i+16] for i in range(0,len(ciphertext1),16)),
        (ciphertext2[i:i+16] for i in range(0,len(ciphertext2),16)),
    ))
    return ciphertext

def aesDecryptCFBdbl(key, plaintext, iv):
    ivs = [iv[:16], iv[16:]]
    ciph1 = AES.new(key, AES.MODE_CFB, iv=ivs[0], segment_size=128)
    ciph2 = AES.new(key, AES.MODE_CFB, iv=ivs[1], segment_size=128)
    plaintext1 = b''.join(plaintext[i:i+16] for i in range(0,len(plaintext),32))
    plaintext2 = b''.join(plaintext[i:i+16] for i in range(16,len(plaintext),32))
    ciphertext1 = ciph1.decrypt(plaintext1)
    ciphertext2 = ciph2.decrypt(plaintext2)
    ciphertext = b''.join( a + b for a,b in zip(
        (ciphertext1[i:i+16] for i in range(0,len(ciphertext1),16)),
        (ciphertext2[i:i+16] for i in range(0,len(ciphertext2),16)),
    ))
    return ciphertext

if __name__ == "__main__":
    key = b'\x00'*(256//8)
    plaintext = b'\x00'*(16*4)
    iv = b'\x00'*28 + b'\x01\x00\x00\x00'

    ciphertext = aesEncryptCFBdbl(key, plaintext, iv)
    assert ciphertext == bytes.fromhex('dc95c078a2408989ad48a21492842087a1d04d6a76f9f7a94d49faa64a87f24408c374848c228233c2b34f332bd2e9d32aae9c468c0a11ec6ccde5efa4541f09')
