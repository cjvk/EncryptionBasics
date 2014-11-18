import Hexadecimal
import DESEncryptValidator
import DESKey

def des_encrypt (block, key):
    """
    Returns encrypt(block), using DES with supplied key

    requires: block is a 64-bit hex-encoded block (string length=16)
              key also is a 64-bit hex encoded block
    """

    # validation
    DESEncryptValidator.DESEncryptValidator().validate(block, key)

    unused = DESKey.DESKey(key)
    
    return

def L (block_bit_tuple):
    if not len(block_bit_tuple) == 64:
        raise ValueError("L: block needs to be 64 bits")
    return block_bit_tuple[0:32]

def R (block_bit_tuple):
    if not len(block_bit_tuple) == 64:
        raise ValueError("R: block needs to be 64 bits")
    return block_bit_tuple[32:64]

