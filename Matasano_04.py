#!/usr/bin/env python

"""4. Detect single-character XOR

One of the 60-character strings at:

  https://gist.github.com/3132713

has been encrypted by single-character XOR. Find it. (Your code from
 #3 should help.)"""

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

# Solve by comparing the relative frequency to that of a standard english sentence.

def sort_by_frequency(msg):
    freqs = collections.Counter()
    for char in msg:
        freqs[char] += 1
    sorted_freqs = sorted(freqs.iteritems(), key=operator.itemgetter(1), reverse=True)
    return sorted_freqs

def score_by_frequency(sentence, letters_by_frequency):
    """The logic used here is that the more english letters in the plaintext, the better it is.
       Letters that occur more frequently are worth more, so having many
       e's will be worth more than having many z's"""

    score = 0
    for letter in sentence:
        if letter in letters_by_frequency:
            score += 26 - letters_by_frequency.index(letter)
    return score


def solve_by_frequency_analysis(raw_ciphertext):
    letters_by_frequency = ['e','t','a','o','i','n','s','h','r','d','l','c','u','m','w','f','g','y','p','b','v','k','j','x','q','z']
    ciphertext = decode_hex(raw_ciphertext)

    sorted_letters = sort_by_frequency(ciphertext)
    best_scoring = None
    best_msg = None
    best_key = None

    size_ciphertext = len(ciphertext)
    for i in range(256):
        key = chr(i)*size_ciphertext
        decrypted = byte_xor(ciphertext, key)
        score = score_by_frequency(decrypted, letters_by_frequency)
        if score > best_scoring:
            best_scoring = score
            best_msg = decrypted
            best_key = key
    return best_scoring, best_msg, best_key


# Solve by seeing which of the 60 strings has the best score
best_scoring = best_msg = best_key = index = None

raw_ciphertexts = open('gistfile4.txt').read().split()

#print raw_ciphertexts

for i, raw_ciphertext in enumerate(raw_ciphertexts):
    score, msg, key = solve_by_frequency_analysis(raw_ciphertext)
    if score > best_scoring:
        best_scoring = score
        best_msg = msg
        best_key = key
        index = i

print "Index is:", index
print "The score was:", best_scoring
print "The key is:", best_key
print "The decrypted message is:", best_msg