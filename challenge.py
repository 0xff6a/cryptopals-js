#!/usr/bin/python3

import struct

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def md_padding(message):
    ml = len(message) * 8
    pad = b'\x80'
    while ((len(message) + len(pad)) * 8) % 512 != 448:
        pad += b'\x00'
    pad += struct.pack(b'>Q', ml)
    return pad

def md_padding_with_mlen(length):
    return md_padding(b'a' * length)

def sha1_modified(message, h0, h1, h2, h3, h4, prefix_length):
    message += md_padding_with_mlen(len(message) + prefix_length)
    for i in range(0, len(message), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        for j in range(16, 80):
            w[j] = left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4        

        for j in range(80):
            if 0 <= j <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= j <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    
            a, b, c, d, e = ((left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff, 
                            a, left_rotate(b, 30), c, d)

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return ('%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)).encode()

def sha1(message):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    ml = len(message) * 8       # message length in bits
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += struct.pack(b'>Q', ml)
    for i in range(0, len(message), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        for j in range(16, 80):
            w[j] = left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4        

        for j in range(80):
            if 0 <= j <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= j <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    
            a, b, c, d, e = ((left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff, 
                            a, left_rotate(b, 30), c, d)

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    return ('%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)).encode()


def sha1_auth(message):
    secret = b'YELLOW SUBMARINE'
    return sha1(secret + message)


def main():
    original = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    sha1hash = sha1_auth(original)
    a = int(sha1hash[0:8], 16)
    b = int(sha1hash[8:16], 16)
    c = int(sha1hash[16:24], 16)
    d = int(sha1hash[24:32], 16)
    e = int(sha1hash[32:40], 16)

    for sec_len in range(0, 64):
        padding = md_padding_with_mlen(len(original) + sec_len)
        newmessage = original + padding + b';admin=true'
        hsh = sha1_modified(b';admin=true', a, b, c, d, e,\
                            len(original) + len(padding) + sec_len)
        if sha1_auth(newmessage) == hsh:
            print(hsh)
            print(list(newmessage))
            print(len(padding))
            print("success")
            break
    else:
        print('sucker')


if __name__ == '__main__':
    main()



