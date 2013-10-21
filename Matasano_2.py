import base64
import binascii
 
str1 = b"1c0111001f010100061a024b53535009181c"
str2 = b"686974207468652062756c6c277320657965"
 
def decode_hex(data):
    return binascii.unhexlify(data)
 
def encode_hex(data):
    return binascii.hexlify(data)
 
def byte_xor(b1, b2):
    b1 = bytearray(b1)
    b2 = bytearray(b2)
    xor_result = []
    for i,j in zip(b1,b2):
        xor_result += [i^j]
    return bytearray(xor_result)
 
b1 = decode_hex(str1)
b2 = decode_hex(str2)
 
result = byte_xor(b1, b2)
 
result = encode_hex(result)

if result == "746865206b696420646f6e277420706c6179":
    print "Success!"
else:
    print "Failed"