#! /usr/bin/env python

"""
12. Byte-at-a-time ECB decryption, Full control version

Copy your oracle function to a new function that encrypts buffers
under ECB mode using a consistent but unknown key (for instance,
assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext,
BEFORE ENCRYPTING, the following string:

  Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
  YnkK

SPOILER ALERT: DO NOT DECODE THIS STRING NOW. DON'T DO IT.

Base64 decode the string before appending it. DO NOT BASE64 DECODE THE
STRING BY HAND; MAKE YOUR CODE DO IT. The point is that you don't know
its contents.

What you have now is a function that produces:

  AES-128-ECB(your-string || unknown-string, random-key)

You can decrypt "unknown-string" with repeated calls to the oracle
function!

Here's roughly how:

a. Feed identical bytes of your-string to the function 1 at a time ---
start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
block size of the cipher. You know it, but do this step anyway.

b. Detect that the function is using ECB. You already know, but do
this step anyways.

c. Knowing the block size, craft an input block that is exactly 1 byte
short (for instance, if the block size is 8 bytes, make
"AAAAAAA"). Think about what the oracle function is going to put in
that last byte position.

d. Make a dictionary of every possible last byte by feeding different
strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
"AAAAAAAC", remembering the first block of each invocation.

e. Match the output of the one-byte-short input to one of the entries
in your dictionary. You've now discovered the first byte of
unknown-string.

f. Repeat for the next byte.
"""

# built-in
import sys
import base64
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
    #import pdb; pdb.set_trace()
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

GLOBAL_FIXED_KEY = rand_aeskey()
SECRET_MSG = base64.b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
                aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
                dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
                YnkK""")


def encryption_oracle12(msg):
    #your-string || unknown-string
    msg = msg + SECRET_MSG
    padded_msg = msg + generate_pkcs7_padding( len(msg), 16)
    return encrypt_ecb(GLOBAL_FIXED_KEY, padded_msg)

#You can decrypt "unknown-string" with repeated calls to the oracle
#function!

#Here's roughly how:

#a. Feed identical bytes of your-string to the function 1 at a time ---
#start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
#block size of the cipher. You know it, but do this step anyway.

previous_size = None
# Choose a large enough number for large block sizes:
for i in range(130):
    size = len(encryption_oracle12("A" * i))
    if not previous_size:
        previous_size = size
        continue
    if size != previous_size:
        block_size = size - previous_size
        print "Block size is:", block_size
        break
else:
    print "No block size found!"
    sys.exit(1)
    
#b. Detect that the function is using ECB. You already know, but do
#this step anyways.

# Cheap method - throw in a huge number of repeated blocks and see if there are repeats
for i in range(10*block_size, 15*block_size):
    ciphertext = encryption_oracle12("A" * i)    
    if detect_mode(ciphertext) != 'ecb':
        print "OOPS"
        print i
        sys.exit(2)

#c. Knowing the block size, craft an input block that is exactly 1 byte
#short (for instance, if the block size is 8 bytes, make
#"AAAAAAA"). Think about what the oracle function is going to put in
#that last byte position.

crafted_block = (block_size-1)*"A"
one_unknown_byte = encryption_oracle12(crafted_block)[:block_size]

#d. Make a dictionary of every possible last byte by feeding different
#strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
#"AAAAAAAC", remembering the first block of each invocation.
mydict = {}
for i in xrange(256):
    mydict[i] = encryption_oracle12(crafted_block + chr(i))[:block_size]

#e. Match the output of the one-byte-short input to one of the entries
#in your dictionary. You've now discovered the first byte of
#unknown-string.

print one_unknown_byte.encode('hex')
print
for byte, encrypted in mydict.iteritems():
    if one_unknown_byte == encrypted:
        #print byte, encrypted.encode('hex')
        last_byte = chr(byte)
        break
else:
    print "None found!"
    sys.exit(3)

print "Byte 1 is:", last_byte
print last_byte == SECRET_MSG[0]

#f. Repeat for the next byte.

crafted_block = (block_size-2)*"A"
one_unknown_byte = encryption_oracle12(crafted_block)[:block_size]
for i in xrange(256):
    if one_unknown_byte == encryption_oracle12(crafted_block + last_byte + chr(i))[:block_size]:
        byte2 = chr(i)
        break
else:
    print "None found!"
    sys.exit(4)

print "Byte 2 is:", byte2
print byte2 == SECRET_MSG[1]
    
# EC: Decrypt the entire block:
decrypted = ""
for byte_num in range(1, 1+block_size):
    crafted_block = (block_size-byte_num)*"A"
    one_unknown_byte = encryption_oracle12(crafted_block)[:block_size]
    for i in xrange(256):
        if one_unknown_byte == encryption_oracle12(crafted_block + decrypted + chr(i))[:block_size]:
            decrypted += chr(i)
            break
            
print "Decrypted block:", decrypted
print  "Success? ", SECRET_MSG[:block_size] == decrypted[:block_size]

# EC: Decrypt the entire message:
decrypted = ""
for block_num in xrange(len(SECRET_MSG)/block_size + 1):
    
    for byte_num in xrange(1, 1+block_size):
        if len(SECRET_MSG) == len(decrypted):
            break
        crafted_block = (block_size-byte_num)*"A"
        one_unknown_byte = encryption_oracle12(crafted_block)[block_num * block_size:(block_num + 1) * block_size]
        for i in xrange(256):
            if one_unknown_byte == encryption_oracle12(crafted_block + decrypted + chr(i))[block_num * block_size:(block_num + 1) * block_size]:
                decrypted += chr(i)
                break

print "Decrypted message:"
print decrypted
print "Success? ", SECRET_MSG == decrypted