#!/usr/bin/env python

"""
13. ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The
routine should take:

   foo=bar&baz=qux&zap=zazzle

and produce:

  {
    foo: 'bar',
    baz: 'qux',
    zap: 'zazzle'
  }

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given
an email address. You should have something like:

  profile_for("foo@bar.com")

and it should produce:

  {
    email: 'foo@bar.com',
    uid: 10,
    role: 'user'
  }

encoded as:

  email=foo@bar.com&uid=10&role=user

Your "profile_for" function should NOT allow encoding metacharacters
(& and =). Eat them, quote them, whatever you want to do, but don't
let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

 (a) Encrypt the encoded user profile under the key; "provide" that
 to the "attacker".

 (b) Decrypt the encoded user profile and parse it.

Using only the user input to profile_for() (as an oracle to generate
"valid" ciphertexts) and the ciphertexts themselves, make a role=admin
profile.
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

BLOCK_SIZE = 16
    
"""
Write a k=v parsing routine, as if for a structured cookie. The
routine should take:

   foo=bar&baz=qux&zap=zazzle

and produce:

  {
    foo: 'bar',
    baz: 'qux',
    zap: 'zazzle'
  }

(you know, the object; I don't care if you convert it to JSON).
"""
def kv_parser(msg):
    mydict = {}
    entries = msg.split('&')
    for entry in entries:
        key, value = entry.split('=')
        mydict[key] = value
    return mydict

print kv_parser('foo=bar&baz=qux&zap=zazzle')

"""    
Now write a function that encodes a user profile in that format, given
an email address. You should have something like:

  profile_for("foo@bar.com")

and it should produce:

  {
    email: 'foo@bar.com',
    uid: 10,
    role: 'user'
  }

encoded as:

  email=foo@bar.com&uid=10&role=user

Your "profile_for" function should NOT allow encoding metacharacters
(& and =). Eat them, quote them, whatever you want to do, but don't
let people set their email address to "foo@bar.com&role=admin".
"""
def profile_for(email):
    email = email.replace('&','')
    email = email.replace('=','')
    return 'email=%s&uid=10&role=user' % email

print profile_for("foo@bar.com")

"""
Now, two more easy functions. Generate a random AES key, then:

 (a) Encrypt the encoded user profile under the key; "provide" that
 to the "attacker".
"""

AES_KEY = rand_aeskey()
def encrypt_profile(profile):
    padded = profile + generate_pkcs7_padding(len(profile), BLOCK_SIZE)
    return encrypt_ecb(AES_KEY, padded)
    
"""
 (b) Decrypt the encoded user profile and parse it.

"""
def decrypt_profile(encrypted_profile):
    decrypted = decrypt_ecb(AES_KEY, encrypted_profile)
    original = remove_pkcs7_padding(decrypted)
    return kv_parser(original)

    
"""
Using only the user input to profile_for() (as an oracle to generate
"valid" ciphertexts) and the ciphertexts themselves, make a role=admin
profile.
"""

# Last bit - attack!
# Strategy: Create two blocks: 1 with a long email address, and another with a bit that has:
# role=admin, and splice them together.

# Example (spaces separate between blocks):
#email=AAAAAAAAAA AAA&uid=10&role= user     # Take blocks 1 and 2
#email=AAAAAAAAAA admin&uid=10&rol e=user   # Take block 2
#email=AAAAAAAAAA AAAA&uid=10&role =user    # Take block 3
# Total:
# email=AAAAAAAAAA AAA&uid=10&role= admin&uid=10&rol =user

print profile_for('AAAAAAAAAAAAA')[:BLOCK_SIZE*2]
print profile_for('AAAAAAAAAAadmin')[BLOCK_SIZE:BLOCK_SIZE*2]
print profile_for('AAAAAAAAAAAAAA')[BLOCK_SIZE*2:BLOCK_SIZE*3]

crafted1 = encrypt_profile(profile_for('AAAAAAAAAAAAA'))[:BLOCK_SIZE*2]
crafted2 = encrypt_profile(profile_for('AAAAAAAAAAadmin'))[BLOCK_SIZE:BLOCK_SIZE*2] 
crafted3 = encrypt_profile(profile_for('AAAAAAAAAAAAAA'))[BLOCK_SIZE*2:BLOCK_SIZE*3]

print decrypt_profile(crafted1 + crafted2 + crafted3)

