import Hexadecimal

class DESEncryptValidator():
    m_hex = Hexadecimal.Hexadecimal()
    def validate_key(self, key):
        if not self.m_hex.is_hex_string(key):
            raise ValueError("des_encrypt: supplied key is not hex format")
        if not len(key) == 16:
            raise ValueError("des_encrypt: supplied key must be length 16 (64 bits)")
        bit_tuple = Hexadecimal.Hexadecimal().hex_string_to_bit_tuple(key)
        if not len(bit_tuple) == 64:
            raise ValueError("really this should not happen")
        # every byte should have an odd number of bits
        while len(bit_tuple) > 0:
            bite = bit_tuple[0:8]
            bit_tuple = bit_tuple[8:]
            num_true = 0
            for bit in bite:
                if bit:
                    num_true = num_true + 1
            if not (num_true & 1) == 1:
                bite_string = Hexadecimal.Hexadecimal().bit_tuple_to_hex_string(bite)
                raise ValueError("odd bits required, key=%s, bite=%s" % (key, bite_string))

    def validate_block(self, block):
        if not self.m_hex.is_hex_string(block):
            raise ValueError("des_encrypt: supplied block is not hex format")
        if not len(block) == 16:
            raise ValueError("des_encrypt: supplied block must be length 16 (64 bits)")
    def validate(self, block, key):
        self.validate_key(key)
        self.validate_block(block)
        pass
    pass
