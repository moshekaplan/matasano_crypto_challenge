#!/usr/bin/env python

#3. Single-character XOR Cipher
#
#The hex encoded string:
#
#      1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
#
#... has been XOR'd against a single character. Find the key, decrypt
#the message.
#
#Write code to do this for you. How? Devise some method for "scoring" a
#piece of English plaintext. (Character frequency is a good metric.)
#Evaluate each output and choose the one with the best score.
#
#Tune your algorithm until this works.

import string
import binascii
import operator
import collections

# The ciphertext in a hex-encoded format
raw_ciphertext = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
 
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

# Solve by seeing how many words in the decrypted ciphertext are in the English dictionary

def read_wordlist(*fnames):
    wordlist = set()
    for fname in fnames:
        new_words = open(fname).read().split()
    	wordlist.update(new_words)
    return wordlist

def score_english_words(msg, wordlist):
    words = msg.split()
    score = 0
    for word in msg.split():
        if word in wordlist:
            score += 1
    return score

def solve_by_containing_english_words(raw_ciphertext):
    ciphertext = decode_hex(raw_ciphertext)
    wordlist = read_wordlist("english_words.txt", "connecticut_yankee.txt")

    best_scoring = None
    best_msg = None
    best_key = None

    size_ciphertext = len(ciphertext)
    for i in range(256):
        key = chr(i)*size_ciphertext
        decrypted = byte_xor(ciphertext, key)
        score = score_english_words(decrypted, wordlist)
        if score > best_scoring:
            best_scoring = score
            best_msg = decrypted
            best_key = key
    print (best_scoring)
    print (best_msg)
    print (best_key)


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
    print (best_scoring)
    print (best_msg)
    print (best_key)


# First approach to solve this challenge
#solve_by_containing_english_words(raw_ciphertext)

# Second approach by frequency analysis:
solve_by_frequency_analysis(raw_ciphertext)