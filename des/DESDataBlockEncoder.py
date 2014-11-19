import Hexadecimal
import DESSBlock

class DESDataBlockEncoder:
    """
    data block encoding

    further details:
    http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
    """
    def __init__(self, data_block = None, des_key=None):
        self.data_block = data_block
        self.des_key = des_key
        self.validate()
        self.derived_data()

    def validate(self):
        if self.data_block is None:
            raise ValueError("data block is not optional!")
        if self.des_key is None:
            raise ValueError("DES key is not optional!")

    def derived_data(self):
        self.data_block_bools = Hexadecimal.Hexadecimal().hex_string_to_bit_tuple(self.data_block)
        self.ip = self.derive_ip()
        self.L, self.R = self.derive_l_r()
        pass

    def derive_l_r(self):
        L = [None] * 17
        R = [None] * 17
        L[0] = self.ip[0:32]
        R[0] = self.ip[32:64]
        for i in range(1, 17):
            L[i] = R[i-1]
            # R[i] = L[i-1]
            R[i] = self.calculate_next_r(L[i-1], R[i-1], self.des_key.derived_keys[i])
        assert(None not in L)
        assert(None not in R)

        return L, R

    def calculate_next_r(self, left_block, right_block, key):
        assert(len(left_block) == 32)
        assert(len(right_block) == 32)
        assert(len(key) == 48)
        f = self.f(right_block, key)
        assert(len(f) == 32)
        next_r = []
        for i in range(0, 32):
            next_r.append(left_block[i] ^ f[i])
        assert(len(next_r) == 32)
        return next_r

    def f(self, right_block, key):
        """
        important part of DES
        f(32-bit block, 48-bit key) = 32-bit output'
        """
        assert(len(right_block) == 32)
        assert(len(key) == 48)
        expanded_right_block = self.e(right_block)
        assert(len(expanded_right_block) == 48)
        combine_xor = []
        for i in range(0, 48):
            combine_xor.append(expanded_right_block[i] ^ key[i])
        assert(len(combine_xor) == 48)

        # now use the S-boxes
        s_encodings = []
        for i in range(0, 8):
            s_block = DESSBlock.DESSBlock(i+1)
            start = i * 6
            end = start + 6
            s_encodings.append(s_block.s_transform(combine_xor[start:end]))
        assert(len(s_encodings) == 8)

        # s_encodings has 8 entries, each of which is a 4-bit tuple/list
        # change them to a simple list of boolean values
        s_encoded_bools = []
        for bool_list in s_encodings:
            for bool in bool_list:
                s_encoded_bools.append(bool)
        assert(len(s_encoded_bools) == 32)

        # p transform
        final_answer = self.p_transform(s_encoded_bools)
            
        return final_answer

    def p_transform(self, block):
        assert(len(block) == 32)
        answer = []
        for pos in self.FINAL_P_TRANSFORM:
            correct_index = pos - 1
            answer.append(block[correct_index])
        assert(len(answer) == 32)
        return answer

    FINAL_P_TRANSFORM = (
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
        )

    def e(self, right_block):
        assert(len(right_block) == 32)
        expanded_right_block = []
        for pos in self.E_MAPPER:
            correct_index = pos - 1
            expanded_right_block.append(right_block[correct_index])
        assert(len(expanded_right_block) == 48)
        return expanded_right_block

    E_MAPPER = (
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
        )

    def derive_ip(self):
        ip = []
        for index in self.IP_PERMUTATION:
            correct_index = index - 1
            ip.append(self.data_block_bools[correct_index])
        return ip

    IP_PERMUTATION = (
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
        )
