#! /usr/bin/env python

"""
9. Implement PKCS#7 padding

Pad any block to a specific block length, by appending the number of
bytes of padding to the end of the block. For instance,

  "YELLOW SUBMARINE"

padded to 20 bytes would be:

  "YELLOW SUBMARINE\x04\x04\x04\x04"

The particulars of this algorithm are easy to find online."""

# Source: https://www.ietf.org/rfc/rfc2315.txt , page 21

def generate_pkcs7_padding(msg_size, block_size):
    bytes_needed = block_size - (msg_size % block_size)
    if bytes_needed > 256:
        raise Exception("Padding for number >=256 are not supported!")
    return bytes_needed*chr(bytes_needed)

def test_padding():
    test_msg = "YELLOW SUBMARINE"
    pad_length = 20
    expected_result = "\x04\x04\x04\x04"
    result = generate_pkcs7_padding(len(test_msg), 20)
    if result != expected_result:
        print "Expected padding to be: %s, instead it was %s" % (expected_result, result)

test_padding()

for i in range(21):
    print repr(generate_pkcs7_padding(i, 20))