#!/usr/bin/python3

import sys, io
from Crypto import Random
from Crypto.Cipher import AES

"""
Requirements:
Must have pycryptodome installed.

Install examples:
python -m pip install pycryptodome
python3 -m pip install pycryptodome
py -3 -m pip install pycryptodome
py -2 -m pip install pycryptodome

Check pip installation example:
python -m pip list | grep crypto

Usage: (-h for help)
python aes_file.py <encrypt/decrypt> <16, 24 or 32 byte long key> <in filename> <out filename>

key should be 32 characters(bytes) long for 256bit AES encryption

"""

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_file(key, in_file, out_file):
    with open(in_file, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    #with open(out_file + ".enc", 'wb') as fo:
    with open(out_file, 'wb') as fo:
        fo.write(enc)

def decrypt_file(key, in_file, out_file):
    with open(in_file, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    #with open(file_name[:-4], 'wb') as fo:
    #with open(out_file + ".orig", 'wb') as fo:
    with open(out_file, 'wb') as fo:
        fo.write(dec)


#key = b'\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18'
#key = bytearray((sys.argv[2]), 'utf-8')

if (sys.argv[1]) == 'encrypt':
    encrypt_file((bytearray((sys.argv[2]), 'utf-8')), (sys.argv[3]), (sys.argv[4]))
elif (sys.argv[1]) == 'decrypt':
    decrypt_file((bytearray((sys.argv[2]), 'utf-8')), (sys.argv[3]), (sys.argv[4]))
elif (sys.argv[1]) == '-h':
    print('aes_file.py <encrypt/decrypt> <16, 24 or 32 byte long key> <in filename> <out filename>')

#encrypt_file('b64beacon.txt', key)
#decrypt_file('to_enc.txt.enc', key)
