#!/usr/bin/env python

"""5. Repeating-key XOR Cipher

Write the code to encrypt the string:

  Burning 'em, if you ain't quick and nimble
  I go crazy when I hear a cymbal

Under the key "ICE", using repeating-key XOR. It should come out to:

  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Get a
feel for it.
"""


import string
import binascii
import operator
import collections


def decode_hex(data):
    return binascii.unhexlify(data)
 
def encode_hex(data):
    return binascii.hexlify(data)
 
def byte_xor(b1, b2):
    b1 = bytearray(b1)
    b2 = bytearray(b2)
    dest = []
    for i,j in zip(b1,b2):
        dest += [i^j]
    return str(bytearray(dest))


# Encrypt the multi-string:

def repeating_key_xor(data, key):
    result = ""
    # First split the data into key-sized segments (besides possibly the last)
    for index in range(0, len(data), len(key)):
        substr = data[index:index + len(key)]
        result += byte_xor(substr, key[:len(substr)])
    return result
    

to_encrypt = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

key = "ICE"

goal = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"


if encode_hex(repeating_key_xor(to_encrypt, key)) == goal:
    print "Success!"
else:
    print "Failed"