#! /usr/bin/env python

"""
8. Detecting ECB

At the following URL are a bunch of hex-encoded ciphertexts:

   https://gist.github.com/3132928

One of them is ECB encrypted. Detect it.

Remember that the problem with ECB is that it is stateless and
deterministic; the same 16 byte plaintext block will always produce
the same 16 byte ciphertext."""

# built-in modules
import base64

ciphertexts = open('gistfile8.txt').read().split()

# Strategy: See if any ciphertext repeats the same 16-byte sequence
# Hex-encoding makes the blocks 32 ascii characters wide
for line_no, ciphertext in enumerate(ciphertexts):
    size = len(ciphertext)
    unique = set(ciphertext[i:i+32] for i in range(0, len(ciphertext), 32))
    if len(unique)*32 != size:
        print "Line:", line_no
        print "Size is:", size
        print (size - len(unique)*32)/32, "repeated blocks"
        print
        print "\n".join(ciphertext[i:i+32] for i in range(0, len(ciphertext), 32))
