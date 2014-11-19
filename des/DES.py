import Hexadecimal
import DESEncryptValidator
import DESKey
import DESDataBlockEncoder

class DES:
    "DES encryption, decryption"
    def __init__(self, key=None):
        DESEncryptValidator.DESEncryptValidator().validate_key(key)
        self.key = key
        self.des_key = DESKey.DESKey(self.key)

    def encrypt(self, block):
        """
        Returns encrypt(block), using DES with supplied key

        requires: block is a 64-bit hex-encoded block (string length=16)
                  key also is a 64-bit hex encoded block
        """
        # validation
        DESEncryptValidator.DESEncryptValidator().validate(block, self.key)
        encoder = DESDataBlockEncoder.DESDataBlockEncoder(block, self.des_key)
        return encoder.encrypted_data_block

    def decrypt(self, block):
        DESEncryptValidator.DESEncryptValidator().validate(block, self.key)
        encoder = DESDataBlockEncoder.DESDataBlockEncoder(block, self.des_key)
        return encoder.decrypt()

def des_encrypt (block, key):
    pass

def des_decrypt (block, key):
    pass
