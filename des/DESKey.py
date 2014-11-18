import Hexadecimal

class DESKey():
    "encapsulate original key, generated keys"
    def __init__(self, key=None):
        self.m_key = key
        self.validate()
        self.derived_data()
    m_hex = Hexadecimal.Hexadecimal()
    def validate(self):
        if self.m_key is None:
            raise ValueError("key is not optional")
        if not self.m_hex.is_hex_string(self.m_key):
            raise ValueError("DES key construction: incorrect format (must be HEX)")
        pass
    def derived_data(self):
        self.m_key_bit_tuple = self.m_hex.hex_string_to_bit_tuple(self.m_key)
        self.k_plus = self.derive_k_plus()
        # initialize c and d
        self.c = [None] * 17
        self.d = [None] * 17
        self.c[0] = self.k_plus[0:28]
        self.d[0] = self.k_plus[28:56]
        self.derive_c_d_1_16()
        pass
    C_D_LEFTSHIFT_TUPLE = ("unused",1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1)
    def derive_c_d_1_16(self):
        for i in range(0, len(self.C_D_LEFTSHIFT_TUPLE)):
            if i == 0:
                continue
            shift_amount = self.C_D_LEFTSHIFT_TUPLE[i]
            self.c[i] = self.left_shift(self.c[i-1], shift_amount)
            self.d[i] = self.left_shift(self.d[i-1], shift_amount)
        assert(None not in self.c)
        assert(None not in self.d)
    def left_shift(self, bit_tuple, num):
        shifted_tuple = bit_tuple[num:] + bit_tuple[0:num]
        assert(len(bit_tuple) == len(shifted_tuple))
        return shifted_tuple
    def derive_k_plus(self):
        temp_list = []
        for map_value in self.K_PLUS_MAPPING_TUPLE:
            correct_index = map_value - 1
            temp_list.append(self.m_key_bit_tuple[correct_index])
        assert(len(temp_list) == 56)
        return tuple(temp_list)
    K_PLUS_MAPPING_TUPLE = (
        # taken from http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
        # 8x7 table called "PC-1"
        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
        )
