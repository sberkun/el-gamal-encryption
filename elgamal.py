import secrets

OUTPUT_CHUNK_SIZE = 32; # 32 bytes, or 256 bits
INPUT_CHUNK_SIZE = OUTPUT_CHUNK_SIZE - 1

P = 115792089237316195423570985008687907853269984665640564039457584007913129639747 # prime, 2**256 - 189
G =  95502723607822415470996255105773198448692078412280229250990790894096242318042 # random, smaller than P - 1



def arToBigInt(ar: bytes):
    return int.from_bytes(ar, "little")

def bigIntToAr(n: int, num_bytes: int):
    return n.to_bytes(num_bytes, "little")

def pow(base: int, exponent: int):
    if exponent == 0:
        return 1
    res = 1
    while exponent > 1:
        if exponent & 1:
            res = (res * base) % P
        base = (base * base) % P
        exponent >>= 1
    return (base * res) % P

def euclid_gcd(a: int, b: int):
    ns = []
    while a > 0 and b > 0:
        if a > b:
            ns.append(a // b)
            a = a % b
        else:
            ns.append(b // a)
            b = b % a
    rx = 1 if a > 0 else 0
    ry = 1 if b > 0 else 0
    g = max(a, b)
    banana = a > b
    for n in ns[::-1]:
        if banana:
            rx -= n * ry
        else:
            ry -= n * rx
        banana = not banana
    return (rx, ry, g)

def random_bytes(n: int):
    return secrets.token_bytes(n)

def encrypt_chunk(num: int, key: int):
    r = 0
    while r <= 5 or r >= P - 2:
        r = arToBigInt(random_bytes(OUTPUT_CHUNK_SIZE))
    return (pow(G, r), (num * pow(key, r)) % P)

def decrypt_chunk(c1: int, c2: int, key: int):
    inverse, _, _ = euclid_gcd(c1, P)
    # inverse + P because inverse could be negative
    return (c2 * pow(inverse % P + P, key)) % P

def make_keypair():
    b = 0
    while b <= 5 or b >= P - 2:
        b = arToBigInt(random_bytes(OUTPUT_CHUNK_SIZE))
    return (bigIntToAr(pow(G, b), OUTPUT_CHUNK_SIZE), b)

def encrypt(raw_msg: bytes, public_key: bytes):
    key = arToBigInt(public_key)

    end_padding = INPUT_CHUNK_SIZE - (len(raw_msg) % INPUT_CHUNK_SIZE) - 1
    new_msg = end_padding.to_bytes(1, 'little') + raw_msg + (b'0' * end_padding)
    # new msg length is (raw_msg.length + 1) rounded up to input chunk size

    num_chunks = len(new_msg) // INPUT_CHUNK_SIZE
    ciphertext = b''
    for a in range(num_chunks):
        temp = new_msg[a * INPUT_CHUNK_SIZE: (a+1) * INPUT_CHUNK_SIZE]
        c1, c2 = encrypt_chunk(arToBigInt(temp) + 5, key)
        ciphertext += bigIntToAr(c1, OUTPUT_CHUNK_SIZE) + bigIntToAr(c2, OUTPUT_CHUNK_SIZE)
    return ciphertext

def decrypt(encrypted_msg: bytes, private_key: int):
    num_chunks = (len(encrypted_msg) // (OUTPUT_CHUNK_SIZE * 2))
    plaintext = b''
    if num_chunks == 0:
        return plaintext
    for a in range(num_chunks):
        c1 = arToBigInt(encrypted_msg[(a*2  ) * OUTPUT_CHUNK_SIZE : (a*2+1) * OUTPUT_CHUNK_SIZE])
        c2 = arToBigInt(encrypted_msg[(a*2+1) * OUTPUT_CHUNK_SIZE : (a*2+2) * OUTPUT_CHUNK_SIZE])
        decrypted = decrypt_chunk(c1, c2, private_key) - 5
        plaintext += bigIntToAr(decrypted, INPUT_CHUNK_SIZE)
    endpoint = len(plaintext) - plaintext[0]
    return plaintext[1:endpoint]
