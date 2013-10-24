#! /usr/bin/env python

"""
10. Implement CBC Mode

In CBC mode, each ciphertext block is added to the next plaintext
block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext
block, is added to a "fake 0th ciphertext block" called the IV.

Implement CBC mode by hand by taking the ECB function you just wrote,
making it encrypt instead of decrypt (verify this by decrypting
whatever you encrypt to test), and using your XOR function from
previous exercise.

DO NOT CHEAT AND USE OPENSSL TO DO CBC MODE, EVEN TO VERIFY YOUR
RESULTS. What's the point of even doing this stuff if you aren't going
to learn from it?

The buffer at:

    https://gist.github.com/3132976

is intelligible (somewhat) when CBC decrypted against "YELLOW
SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)"""

# built-in
import base64


# PyCrypto
import Crypto.Cipher.AES

def byte_xor(b1, b2):
    b1 = bytearray(b1)
    b2 = bytearray(b2)
    dest = []
    for i,j in zip(b1,b2):
        dest += [i^j]
    return str(bytearray(dest))

def chunks(chunkable, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(chunkable), n):
        yield chunkable[i:i+n]
    
def encrypt_ecb(key, message):
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    return cipher.encrypt(message)

def decrypt_ecb(key, ciphertext):
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def generate_pkcs7_padding(msg_size, block_size):
    bytes_needed = block_size - (msg_size % block_size)
    if bytes_needed > 256:
        raise Exception("Padding for number >=256 are not supported!")
    return bytes_needed*chr(bytes_needed)
    
def encrypt_cbc(key, iv, message):
    # Steps:
    # 1) Pad to ensure data is a multiple of block_size
    # 2) Split data into block_size blocks
    # 3) Then for each block:
    #   a) XOR each block with the previous ciphertext (IV for the first)
    #   b) ECB-Encrypt each block
    # 4) Combine together for result.
    # Notes: Assuming it's AES-128, like earlier.
    block_size = 128/8
    
    # 1) Pad to ensure data is a multiple of block_size
    #msg_size = len(message)
    #message = message + generate_pkcs7_padding(msg_size, block_size)
    
    # 2) Split data into block_size blocks
    # 3) Then for each block:
    ciphertexts = []
    prev_ciphertext = iv
    for plaintext_block in chunks(message, block_size):
        #   a) XOR each block with the previous ciphertext (IV for the first)    
        xor_result = byte_xor(plaintext_block, prev_ciphertext)
        #   b) ECB-Encrypt each block
        encrypt_result = encrypt_ecb(key, xor_result)

        prev_ciphertext = encrypt_result
        ciphertexts = ciphertexts + [encrypt_result]

    # 4) Combine together for a final result.
    return ''.join(ciphertexts)
    
def decrypt_cbc(key, iv, ciphertext):
    # Steps:
    # 1) Ensure data is a multiple of block_size
    # 2) Split data into block_size blocks
    # 3) Then for each block:
    #   a) ECB-decrypt each block
    #   b) XOR with previous ciphertext block (IV for first)
    # 4) Combine together for result.
    # Notes: Assuming it's AES-128, like earlier.
    block_size = 128/8
    
    # 1) Ensure data is a multiple of block_size
    if len(ciphertext) % block_size != 0:
        raise Exception("Ciphertext is not a multiple of the block size")
    
    # 2) Split data into block_size blocks
    # 3) Then for each block:
    messages = []
    prev_ciphertext = iv
    for ciphertext_block in chunks(ciphertext, block_size):
        #   a) ECB-decrypt each block
        decrypted_result = decrypt_ecb(key, ciphertext_block)
        #   b) XOR with previous ciphertext block (IV for first)
        decrypted_block = byte_xor(decrypted_result, prev_ciphertext)
        prev_ciphertext = ciphertext_block
        
        messages = messages + [decrypted_block]
    # 4) Combine together for result.
    return ''.join(messages)
    
iv = '\x00'*(128/8)
key = "YELLOW SUBMARINE"

ciphertext = base64.b64decode(open('gistfile10.txt').read())

print decrypt_cbc(key,iv,ciphertext)
