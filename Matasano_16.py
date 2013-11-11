"""
16. CBC bit flipping

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the
string:
        "comment1=cooking%20MCs;userdata="
and append the string:
    ";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block
length and encrypt it under the random AES key.

The second function should decrypt the string and look for the
characters ";admin=true;" (or, equivalently, decrypt, split the string
on ;, convert each resulting string into 2-tuples, and look for the
"admin" tuple. Return true or false based on whether the string exists.

If you've written the first function properly, it should not be
possible to provide user input to it that will generate the string the
second function is looking for.

Instead, modify the ciphertext (without knowledge of the AES key) to
accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a
ciphertext block:

* Completely scrambles the block the error occurs in

* Produces the identical 1-bit error (/edit) in the next ciphertext
 block.

Before you implement this attack, answer this question: why does CBC
mode have this property?

// ------------------------------------------------------------
"""



import Crypto.Cipher.AES

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
    
def kv_parser(msg):
    print msg
    mydict = {}
    entries = msg.split(';')
    for entry in entries:
        key, value = entry.split('=')
        mydict[key] = value
    return mydict
    

BLOCK_SIZE = 16
AES_KEY = rand_aeskey()
IV = rand_bytes(BLOCK_SIZE)

"""
The first function should take an arbitrary input string, prepend the
string:
        "comment1=cooking%20MCs;userdata="
and append the string:
    ";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block
length and encrypt it under the random AES key.
"""

def encoder(userdata):
    prepend = "comment1=cooking%20MCs;userdata="
    append  = ";comment2=%20like%20a%20pound%20of%20bacon"
    
    userdata = userdata.replace(';','')
    userdata = userdata.replace('=','')
    
    msg = prepend + userdata + append
    
    padded_msg = msg + generate_pkcs7_padding(len(msg), BLOCK_SIZE)
    return encrypt_cbc(AES_KEY, IV, padded_msg)
    
"""
The second function should decrypt the string and look for the
characters ";admin=true;" (or, equivalently, decrypt, split the string
on ;, convert each resulting string into 2-tuples, and look for the
"admin" tuple. Return true or false based on whether the string exists.
"""
def decoder(ciphertext):
    padded_msg = decrypt_cbc(AES_KEY, IV, ciphertext)
    msg = remove_pkcs7_padding(padded_msg)
    kv = kv_parser(msg)
    return 'admin' in kv and kv['admin'] == 'true'


"""
If you've written the first function properly, it should not be
possible to provide user input to it that will generate the string the
second function is looking for.

Instead, modify the ciphertext (without knowledge of the AES key) to
accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a
ciphertext block:

* Completely scrambles the block the error occurs in

* Produces the identical 1-bit error (/edit) in the next ciphertext
 block.

Before you implement this attack, answer this question: why does CBC
mode have this property?
"""


# Approach: Add in another block that we can make include: admin=true
# Blocks:
#   comment1=cooking %20MCs;userdata=
#   AAAAA;admin=true
#   ;comment2=%20like%20a%20pound%20of%20bacon

# But we can't include a semicolon. So instead:
#   AAAAA:admin=true
# A semicolon is 0x3B
# A colon is 0x3A
# So all we need to do is flip the last bit of that byte, and we have a ;

# Likewise, we can't include =, which is 0x3D
# To be lazy, we can include a '>', which is also one bit off:
#   AAAAA:admin<true
# We will therefore flip the last bit of bytes 6 and 12 in block 2.

def flip_lsb(byte):
    return chr(ord(byte) ^ 1)

payload = "AAAAA:admin<true"
ciphertext = encoder(payload)

# We need to alter the second block to cause a change in the 3rd.
colon_location = BLOCK_SIZE + payload.find(':')
angle_location = BLOCK_SIZE + payload.find('<')

altered = ciphertext[:colon_location] + flip_lsb(ciphertext[colon_location]) + ciphertext[colon_location + 1 : angle_location] + flip_lsb(ciphertext[angle_location]) + ciphertext[ angle_location + 1:]

print decoder(altered)