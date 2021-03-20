def xor_bytes(b1, b2):
    return bytes(map(lambda x: x[0]^x[1],zip(b1,b2)))

def neg_bytes(b):
    return bytes(map(lambda x: ~x & 0xff, b))
