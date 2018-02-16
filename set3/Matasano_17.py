"""
17. The CBC padding oracle

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10
strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

generate a random AES key (which it should save for all future
encryptions), pad the string out to the 16-byte AES block size and
CBC-encrypt it under that key, providing the caller the ciphertext and
IV.

The second function should consume the ciphertext produced by the
first function, decrypt it, check its padding, and return true or
false depending on whether the padding is valid.

This pair of functions approximates AES-CBC encryption as its deployed
serverside in web applications; the second function models the
server's consumption of an encrypted session token, as if it was a
cookie.

It turns out that it's possible to decrypt the ciphertexts provided by
the first function.

The decryption here depends on a side-channel leak by the decryption
function.

The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't
re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is
valid padding, and occur in 1/256 trials of "randomized" plaintexts
produced by decrypting a tampered ciphertext.

02h in isolation is NOT valid padding.

02h 02h IS valid padding, but is much less likely to occur randomly
than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid
padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are
"padded". Padding oracles have nothing to do with the actual padding
on a CBC plaintext. It's an attack that targets a specific bit of code
that handles decryption. You can mount a padding oracle on ANY CBC
block, whether it's padded or not.

"""
import base64

import Crypto.Cipher.AES

import random


def rand_byte():
    return chr(random.randint(0, 255))


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
    return bytes_needed * chr(bytes_needed)


def strip_pkcs7_padding(msg):
    last = msg[-1]

    if len(msg) < ord(last):
        raise Exception("Not enough bytes!")

    padding = msg[-ord(last):]
    if len(padding) != ord(last):
        raise Exception("This shouldn't be possible!")

    if padding != ord(last) * last:
        raise Exception("Invalid padding!")
    return msg[:-ord(last)]


def byte_xor(b1, b2):
    b1 = bytearray(b1)
    b2 = bytearray(b2)
    dest = []
    for i, j in zip(b1, b2):
        dest += [i ^ j]
    return str(bytearray(dest))


def chunks(chunkable, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(chunkable), n):
        yield chunkable[i:i + n]


def encrypt_cbc(key, iv, message):
    # Steps:
    # 1) Pad to ensure data is a multiple of block_size
    # 2) Split data into block_size blocks
    # 3) Then for each block:
    #   a) XOR each block with the previous ciphertext (IV for the first)
    #   b) ECB-Encrypt each block
    # 4) Combine together for result.
    # Notes: Assuming it's AES-128, like earlier.
    block_size = 128 / 8

    # 1) Pad to ensure data is a multiple of block_size
    # msg_size = len(message)
    # message = message + generate_pkcs7_padding(msg_size, block_size)

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
    block_size = 128 / 8

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


def encrypt_cbc(key, iv, message):
    # Steps:
    # 1) Pad to ensure data is a multiple of block_size
    # 2) Split data into block_size blocks
    # 3) Then for each block:
    #   a) XOR each block with the previous ciphertext (IV for the first)
    #   b) ECB-Encrypt each block
    # 4) Combine together for result.
    # Notes: Assuming it's AES-128, like earlier.
    block_size = 128 / 8

    # 1) Pad to ensure data is a multiple of block_size
    # msg_size = len(message)
    # message = message + generate_pkcs7_padding(msg_size, block_size)

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
    block_size = 128 / 8

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


BLOCK_SIZE = 16
AES_KEY = rand_aeskey()

def encrypt_random_string():
    # The first function should select at random one of the following 10 strings:
    # generate a random AES key (which it should save for all future encryptions),
    # pad the string out to the 16-byte AES block size and
    # CBC-encrypt it under that key, providing the caller the ciphertext and IV.

    b64_messages = """MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93""".split()
    messages = [base64.b64decode(b64) for b64 in b64_messages]
    msg = random.choice(messages)
    padded_msg = msg + generate_pkcs7_padding(len(msg), BLOCK_SIZE)
    IV = rand_bytes(BLOCK_SIZE)
    ciphertext = encrypt_cbc(AES_KEY, IV, padded_msg)
    return ciphertext, IV


def decrypt_and_validate_padding(ciphertext, IV, key):
    # The second function should consume the ciphertext produced by the first function,
    # decrypt it,
    # check its padding, and
    # return true or false depending on whether the padding is valid.
    plaintext = decrypt_cbc(AES_KEY, IV, ciphertext)
    try:
        strip_pkcs7_padding(plaintext)
        return True
    except:
        return False

ciphertext, IV = encrypt_random_string()
print decrypt_and_validate_padding(ciphertext, IV, AES_KEY)

