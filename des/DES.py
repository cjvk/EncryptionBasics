import string
import re

def des_encrypt (block, key):
    """
    Returns encrypt(block), using DES with supplied key

    requires: block is a 64-bit hex-encoded block (string length=16)
              key also is a 64-bit hex encoded block
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

