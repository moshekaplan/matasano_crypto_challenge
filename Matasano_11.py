#! /usr/bin/env python

"""
11. Write an oracle function and use it to detect ECB.

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random
bytes.

Write a function that encrypts data under an unknown key --- that is,
a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
 => [MEANINGLESS JIBBER JABBER]

Under the hood, have the function APPEND 5-10 bytes (count chosen
randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and
under CBC the other half (just use random IVs each time for CBC). Use
rand(2) to decide which to use.

Now detect the block cipher mode the function is using each time.
"""

# built-in
import random

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


def generate_pkcs7_padding(msg_size, block_size):
    bytes_needed = block_size - (msg_size % block_size)
    if bytes_needed > 256:
        raise Exception("Padding for number >=256 are not supported!")
    return bytes_needed*chr(bytes_needed)

def rand_byte():
    return chr(random.randint(0,255))

def rand_bytes(amount):
    return ''.join([rand_byte() for i in range(amount)])

#Write a function to generate a random AES key; that's just 16 random bytes.
def rand_aeskey():
    return rand_bytes(16)

#Write a function that encrypts data under an unknown key --- that is,
# a function that generates a random key and encrypts under it.
# The function should look like:

#encryption_oracle(your-input)
# => [MEANINGLESS JIBBER JABBER]


def encryption_oracle(msg):
    key = rand_aeskey()
    iv = rand_bytes(16)
    #Under the hood, have the function APPEND 5-10 bytes (count chosen
    #randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.
    before = rand_bytes(random.randint(5,10))
    after = rand_bytes(random.randint(5,10))

    complete_msg = before + msg + after
    
    padded_msg = complete_msg + generate_pkcs7_padding( len(complete_msg), 16)
    
    #Now, have the function choose to encrypt under ECB 1/2 the time, and
    #under CBC the other half (just use random IVs each time for CBC). Use
    #rand(2) to decide which to use.

    if random.choice([True, False]):
        return encrypt_ecb(key, padded_msg), 'ecb'
    else:
        return encrypt_cbc(key, iv, padded_msg), 'cbc'

#Now detect the block cipher mode the function is using each time.
def detect_mode(ciphertext):
    unique = set(ciphertext[i:i+16] for i in range(0, len(ciphertext), 16))
    # One of the goals with CBC is that even if there are repeated
    # blocks in the plaintext, it won't repeat in the ciphertext.
    # As such, we can (almost) pretend that CBC-mode should give us 
    # "random" output, with the chance of a collision being related to
    # the birthday problem.
    
    # Comparatively, ECB mode will have a collision as soon as the
    # same plaintext block is repeated. Since it's only a 16-byte block
    # we expect many more collisions than from the birthday problem
    num_blocks = len(ciphertext)/16
    num_possibilities = 2**256
    birthday_collisions = num_blocks*(1-(1 - 1.0/num_possibilities)**(num_blocks-1))
    actual_collisions = len(ciphertext)/16 - len(unique)
    # For an arbitrary number, let's say there are 10 as many, we'll
    # consider that significant
    if (actual_collisions > 10 * birthday_collisions) and (actual_collisions - birthday_collisions > 2):
        return 'ecb'
    else:
        return 'cbc'

yankee = open('connecticut_yankee.txt','r').read()

for i in range(1000):
    if i %50 == 0:
        print i
    encrypted, method = encryption_oracle(yankee)
    detected = detect_mode(encrypted)
    if method != detected:
        print method, detected
    