#!/usr/bin/python3

import sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import ARC4
from base64 import b64encode, b64decode

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

Encryption Key should be 32 characters(bytes) long for 256bit AES encryption
Random 16 byte IV is written to the start of the encrypted message

"""

def aes_encrypt(message, key, key_size=256):
    message = pad(message, AES.block_size, style='pkcs7')
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size, style='pkcs7')
    return plaintext

def aes_encrypt_file(key, in_file, out_file):
    with open(in_file, 'rb') as fo:
        plaintext = fo.read()
    #plaintext = b64encode(plaintext)
    enc = aes_encrypt(plaintext, key)
    #enc = b64encode(enc)
    with open(out_file, 'wb') as fo:
        fo.write(enc)
    print(f'[*] Read File Bytes: {len(plaintext)}')
    print(f'[*] AES Encrypted File Bytes: {len(enc)}')
    print("[*] AES encrypted file written to: " + out_file)

def aes_decrypt_file(key, in_file, out_file):
    with open(in_file, 'rb') as fo:
        ciphertext = fo.read()
    #ciphertext = b64decode(ciphertext)
    dec = aes_decrypt(ciphertext, key)
    #dec = b64decode(dec)
    with open(out_file, 'wb') as fo:
        fo.write(dec)
    print(f'[*] Read File Bytes: {len(ciphertext)}')
    print(f'[*] AES Decrypted File Bytes: {len(dec)}')
    print("[*] AES decrypted file written to: " + out_file)

def rc4_encrypt_file(key, in_file, out_file):
    with open(in_file, 'rb') as fo:
        plaintext = fo.read()
    #plaintext = b64encode(plaintext)
    cipher = ARC4.new(key)
    enc = cipher.encrypt(plaintext)
    #enc = b64encode(enc)
    with open(out_file, 'wb') as fo:
        fo.write(enc)
    print(f'[*] Read File Bytes: {len(plaintext)}')
    print(f'[*] RC4 Encrypted File Bytes: {len(enc)}')
    print("[*] RC4 encrypted file written to: " + out_file)

def rc4_decrypt_file(key, in_file, out_file):
    with open(in_file, 'rb') as fo:
        ciphertext = fo.read()
    #ciphertext = b64decode(ciphertext)
    cipher = ARC4.new(key)
    dec = cipher.encrypt(ciphertext)
    #dec = b64decode(dec)
    with open(out_file, 'wb') as fo:
        fo.write(dec)
    print(f'[*] Read File Bytes: {len(ciphertext)}')
    print(f'[*] RC4 Decrypted File Bytes: {len(dec)}')
    print("[*] RC4 decrypted file written to: " + out_file)

if len(sys.argv) < 5:
    print('Usage: encrypt_file.py <aes/rc4> <encrypt/decrypt> <key> <input file> <output file>')
    print('AES key: 16, 24 or 32 byte long key')
    print('RC4 key: Minimum 5 byte length value or phrase. Phrase with spaces needs to be in ""')
elif (sys.argv[1]) == 'aes' and (sys.argv[2]) == 'encrypt':
    aes_encrypt_file((bytearray((sys.argv[3]), 'utf-8')), (sys.argv[4]), (sys.argv[5]))
elif (sys.argv[1]) == 'aes' and (sys.argv[2]) == 'decrypt':
    aes_decrypt_file((bytearray((sys.argv[3]), 'utf-8')), (sys.argv[4]), (sys.argv[5]))
elif (sys.argv[1]) == 'rc4' and (sys.argv[2]) == 'encrypt':
    rc4_encrypt_file((bytearray((sys.argv[3]), 'utf-8')), (sys.argv[4]), (sys.argv[5]))
elif (sys.argv[1]) == 'rc4' and (sys.argv[2]) == 'decrypt':
    rc4_decrypt_file((bytearray((sys.argv[3]), 'utf-8')), (sys.argv[4]), (sys.argv[5]))