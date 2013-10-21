#!/usr/bin/env python
# Encoding: ASCII

"""6. Break repeating-key XOR

The buffer at the following location:

 https://gist.github.com/3132752

is base64-encoded repeating-key XOR. Break it.

Here's how:

a. Let KEYSIZE be the guessed length of the key; try values from 2 to
(say) 40.

b. Write a function to compute the edit distance/Hamming distance
between two strings. The Hamming distance is just the number of
differing bits. The distance between:

  this is a test

and:

  wokka wokka!!!

is 37.

c. For each KEYSIZE, take the FIRST KEYSIZE worth of bytes, and the
SECOND KEYSIZE worth of bytes, and find the edit distance between
them. Normalize this result by dividing by KEYSIZE.

d. The KEYSIZE with the smallest normalized edit distance is probably
the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
values. Or take 4 KEYSIZE blocks instead of 2 and average the
distances.

e. Now that you probably know the KEYSIZE: break the ciphertext into
blocks of KEYSIZE length.

f. Now transpose the blocks: make a block that is the first byte of
every block, and a block that is the second byte of every block, and
so on.

g. Solve each block as if it was single-character XOR. You already
have code to do this.

h. For each block, the single-byte XOR key that produces the best
looking histogram is the repeating-key XOR key byte for that
block. Put them together and you have the key.
"""

import base64
import string
import binascii
import operator
import itertools
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


# Encrypt the multi-string:

def repeating_key_xor(data, key):
    result = ""
    # First split the data into key-sized segments (besides possibly the last)
    for index in range(0, len(data), len(key)):
        substr = data[index:index + len(key)]
        result += byte_xor(substr, key[:len(substr)])
    return result


#b. Write a function to compute the edit distance/Hamming distance
#between two strings. The Hamming distance is just the number of
#differing bits. The distance between:
#
#  this is a test
#
#and:
#
#  wokka wokka!!!
#
#is 37.

def bit_distance(str1, str2):
    distance = 0
    xor_result = byte_xor(str1, str2)
    for char in xor_result:
        for bit in bin(ord(char))[2:]:
            if bit == "1":
                distance += 1
    return distance

def test_bit_distance():
    if bit_distance("this is a test", "wokka wokka!!!") != 37:
        print "bit distance test failed"

test_bit_distance()


#g. Solve each block as if it was single-character XOR. You already
#have code to do this.

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

def solve_by_frequency_analysis(ciphertext):
    letters_by_frequency = ['e','t','a','o','i','n','s','h','r','d','l','c','u','m','w','f','g','y','p','b','v','k','j','x','q','z']
   
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
            best_key = chr(i)
    return best_scoring, best_msg, best_key


# a. Let KEYSIZE be the guessed length of the key; try values from 2 to
#(say) 40.

#c. For each KEYSIZE, take the FIRST KEYSIZE worth of bytes, and the
#SECOND KEYSIZE worth of bytes, and find the edit distance between
#them. Normalize this result by dividing by KEYSIZE.

#d. The KEYSIZE with the smallest normalized edit distance is probably
#the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
#values. Or take 4 KEYSIZE blocks instead of 2 and average the
#distances.

def get_keysize_distance_pairs(ciphertext):
    keysize_distance_pairs = []

    for keysize in range(2, 40):
        first_keysize = ciphertext[:keysize]
        second_keysize = ciphertext[keysize:keysize*2]
        normalized_distance = 1.0*bit_distance(first_keysize, second_keysize)/keysize
    
        keysize_distance_pairs.append((keysize, normalized_distance))
    
    return sorted(keysize_distance_pairs, key=operator.itemgetter(1))



#e. Now that you probably know the KEYSIZE: break the ciphertext into
#blocks of KEYSIZE length.

def split_into_keysize_blocks(ciphertext, keysize):
    keysize_blocks = []
    for index in range(0, len(ciphertext), keysize):
        keysize_blocks.append(ciphertext[index:index + keysize])
    return keysize_blocks

#f. Now transpose the blocks: make a block that is the first byte of
#every block, and a block that is the second byte of every block, and
#so on.

# Warning: There are None's in the shorter columns!
def transpose_blocks(blocks):
    return [transposed for transposed in itertools.izip_longest(*blocks)]


# To clean up false positives, let's use a wordlist, and require a word
# for every 30 characters

def read_wordlist(*fnames):
    wordlist = set()
    for fname in fnames:
        new_words = open(fname).read().split()
    	wordlist.update(new_words)
    return wordlist

def score_english_words(msg, wordlist):
    # First strip the punctuation
    exclude = set(string.punctuation)
    msg = ''.join(ch for ch in msg if ch not in exclude)

    words = msg.split()
    score = 0
    for word in msg.split():
        if word in wordlist:
            score += 1
    return score



#h. For each block, the single-byte XOR key that produces the best
#looking histogram is the repeating-key XOR key byte for that
#block. Put them together and you have the key.

wordlist = read_wordlist("english_words.txt", "connecticut_yankee.txt")

ciphertext = base64.b64decode(open('gistfile6.txt').read())

keysize_distance_pairs = get_keysize_distance_pairs(ciphertext)

for keysize, distance in keysize_distance_pairs:
    blocks = split_into_keysize_blocks(ciphertext, keysize)
    transposed_blocks = transpose_blocks(blocks)
    key = ""
    
    for block in transposed_blocks:
        block = "".join(char for char in block if char is not None)
        best_scoring, best_msg, partial_key = solve_by_frequency_analysis(block)
        key += partial_key

    # We'll assume we have a solution if there is at least one dictionary word every 40 chars
    if score_english_words(repeating_key_xor(ciphertext, key), wordlist)*40 > len(ciphertext):
        print "Key:", key
        print repeating_key_xor(ciphertext, key)
        break