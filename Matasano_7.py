#! /usr/bin/env python

"""
7. AES in ECB Mode

The Base64-encoded content at the following location:

    https://gist.github.com/3132853

Has been encrypted via AES-128 in ECB mode under the key

    "YELLOW SUBMARINE".

(I like "YELLOW SUBMARINE" because it's exactly 16 bytes long).

Decrypt it.

Easiest way:

Use OpenSSL::Cipher and give it AES-128-ECB as the cipher."""

# built-in modules
import base64

# PyCrypto
import Crypto.Cipher.AES

key = "YELLOW SUBMARINE"
cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)

ciphertext = base64.b64decode(open('gistfile7.txt').read())

print cipher.decrypt(ciphertext)