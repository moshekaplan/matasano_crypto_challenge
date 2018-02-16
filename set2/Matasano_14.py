#!/usr/bin/env python

"""
14. Byte-at-a-time ECB decryption, Partial control version

Take your oracle function from #12. Now generate a random count of
random bytes and prepend this string to every plaintext. You are now
doing:

  AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.

What's harder about doing this?

How would you overcome that obstacle? The hint is: you're using
all the tools you already have; no crazy math is required.

Think about the words "STIMULUS" and "RESPONSE".

"""

# Approach: 
# 1) Query the oracle to find out how long the random prefix is
# 2) Use the code from problem 12 to break the scheme.

import Crypto.Cipher.AES

import sys
import base64
import random

def rand_byte():
    return chr(random.randint(0,255))

def rand_bytes(amount):
    return ''.join([rand_byte() for i in range(amount)])

def rand_aeskey():
    return rand_bytes(16)

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

def remove_pkcs7_padding(msg):
    last_byte = ord(msg[-1])
    return msg[:-last_byte]

    
"""
Take your oracle function from #12. Now generate a random count of
random bytes and prepend this string to every plaintext. You are now
doing:

  AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
"""  
    
GLOBAL_FIXED_KEY = rand_aeskey()
GLOBAL_FIXED_PREFIX = rand_bytes(random.randint(0,1000))
SECRET_MSG = base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                YnkK""")

def encryption_oracle(msg):
    # random-prefix || attacker-controlled || target-bytes
    msg = GLOBAL_FIXED_PREFIX + msg + SECRET_MSG
    padded_msg = msg + generate_pkcs7_padding( len(msg), 16)
    return encrypt_ecb(GLOBAL_FIXED_KEY, padded_msg)    

# Approach: 
# 1) Query the oracle to find out how long the random prefix is
# 2) Use the code from problem 12 to break the scheme.

    
BLOCK_SIZE = 16

# 1) Query the oracle to find out how long the random prefix is


# Choose a large enough number for large block sizes:
def find_prefix_size(oracle):
    """Takes an encryption oracle and attempts to find the block size through making repeated queries
    
    The trick this will use is to keep on appending bytes, until it requires the addition of a new block.
    Say we had a random number of 15 bytes, X bytes under our control, and 10 after:
    15 + x + 10 = 25 + x, requires 2 blocks
    When it reaches 32 bytes, it will require 3 blocks (which has a length of 48).
    
    So we can determine that we needed to add 7 bytes to create a new block.
    That means that:
    total = random-prefix || attacker-controlled || target-bytes || padding
    
    total = 48
    attacker-controlled = 7
    target-bytes = 10
    padding = 16

    48 - 16 - 7 - 10 = 15
    """
    
    MAX_PREFIX_SIZE = 1024   # For now, let's assume it's <= 1024
    
    previous_size = None
    for i in range(MAX_PREFIX_SIZE):
        size = len(encryption_oracle("A" * i))
        if not previous_size:
            previous_size = size
            continue
        if size != previous_size:
            # We found it!
            pad_size = i
            break
    else:
        raise Exception("Unknown size!")
    return size - pad_size - len(SECRET_MSG) - BLOCK_SIZE

prefix_size = find_prefix_size(encryption_oracle)

print "Calculated prefix:", prefix_size
print "Actual prefix size:", len(GLOBAL_FIXED_PREFIX)

# Step 2: Now that we know the prefix size, we can attack!
# Simplest approach: Pad out the remainder of that block, truncate from there, and then use the exact same code!

end_prefix_padding = (BLOCK_SIZE - (prefix_size % BLOCK_SIZE)) % BLOCK_SIZE

print "Required number of bytes:", end_prefix_padding
print "%16 after adding padding:", ( prefix_size + end_prefix_padding) % BLOCK_SIZE

starting_block_number = (prefix_size + end_prefix_padding) / BLOCK_SIZE

# Decrypt the target-bytes: random-prefix || attacker-controlled || target-bytes
decrypted = ""

# Now skip everything before starting_block_number
for block_num in xrange(starting_block_number, (prefix_size + end_prefix_padding + len(SECRET_MSG))/BLOCK_SIZE + 2):
    for byte_num in xrange(1, 1 + BLOCK_SIZE):
        if len(SECRET_MSG) == len(decrypted):
            break
        crafted_block = (end_prefix_padding + BLOCK_SIZE - byte_num)*"A"
        one_unknown_byte = encryption_oracle(crafted_block)[block_num * BLOCK_SIZE:(block_num + 1) * BLOCK_SIZE]
        for i in xrange(256):
            if one_unknown_byte == encryption_oracle(crafted_block + decrypted + chr(i))[block_num * BLOCK_SIZE:(block_num + 1) * BLOCK_SIZE]:
                decrypted += chr(i)
                break

print "Decrypted message:"
print decrypted
print "Success? ", SECRET_MSG == decrypted