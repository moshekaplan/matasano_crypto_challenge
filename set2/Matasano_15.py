"""
15. PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid
PKCS#7 padding, and strips the padding off.

The string:

    "ICE ICE BABY\x04\x04\x04\x04"

has valid padding, and produces the result "ICE ICE BABY".

The string:

    "ICE ICE BABY\x05\x05\x05\x05"

does not have valid padding, nor does:

     "ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby,
make your function throw an exception on bad padding.
"""

def strip_pkcs7_padding(msg):
    last = msg[-1]

    if len(msg) < ord(last):
        raise Exception("Not enough bytes!")

    padding = msg[-ord(last):]
    if len(padding) != ord(last):
        raise Exception("This shouldn't be possible!")
    
    if padding != ord(last)*last:
        raise Exception("Invalid padding!")
    return msg[:-ord(last)]

def test_stripper():
    if strip_pkcs7_padding("ICE ICE BABY\x04\x04\x04\x04") != "ICE ICE BABY":
        print "Failed 1"
        return False
        
    try:
        strip_pkcs7_padding("ICE ICE BABY\x05\x05\x05\x05")
    except:
        pass
    else:
        print "Failed 2"
        return False
        
    try:
        strip_pkcs7_padding("ICE ICE BABY\x01\x02\x03\x04")
    except:
        pass
    else:
        print "Failed 3"
        return False
    
    return True
    
if test_stripper():
    print "All good"