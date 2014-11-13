import string
import re

# assumes a block size of 64 bits
# can either use base-64 encoding or hex encoding
# let's use hex encoding

def des_encrypt (block, key):
    """
    Returns encrypt(block), using DES with supplied key

    requires: block represents a 64-bit block
              block is hex-encoded so must only contain [0-9A-Fa-f]
              block therefore must be 16 characters in length
              key also is 64-bit hex encoding, so same requirements
    """

    if not is_hex_string(block):
        raise ValueError("des_encrypt: supplied block is not hex format")

    if not is_hex_string(key):
        raise ValueError("des_encrypt: supplied key is not hex format")

    if not len(block) == 16:
        raise ValueError("des_encrypt: supplied block must be length 16 (64 bits)")

    if not len(key) == 16:
        raise ValueError("des_encrypt: supplied key must be length 16 (64 bits)")

    # validation complete
    
    return

def is_hex_string(s):
    m = re.search('^[0-9a-fA-F]*$', s)
    return not m is None

def test_is_hex_string():
    assert is_hex_string("abc") == True
    assert is_hex_string("abcx") == False
    assert is_hex_string("AbC0239428398432") == True
    assert is_hex_string("") == True
    print "is_hex_string: all tests passed!"

des_encrypt("384792aaa37ABCCC", "92387ABCDEFabcde")
test_is_hex_string()
