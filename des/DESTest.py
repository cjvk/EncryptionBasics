import DES
import Hexadecimal
import DESEncryptValidator
import DESKey

import unittest

class DESTest(unittest.TestCase):

    def setUp(self):
        pass

    def test_deskey_derive_cd(self):
        # using same stuff as previous test - since if it is in C
        # then there will be no offset
        key = DESKey.DESKey("0101010101010110")
        # 60th bit mapped to 25th in k_plus which is in C
        expected_bits_set = (25-1,
                             24-1, 23-1, # two 1's
                             21-1, 19-1, 17-1, 15-1, 13-1, 11-1, # 6 2's
                             10-1, # 1 1
                             8-1, 6-1, 4-1, 2-1, 28-1, 26-1, # 6 2's
                             25-1 # 1 1
                             )
        self.assertTrue(len(expected_bits_set) == 17)

        cd_keys = key.cd.keys()
        self.assertTrue(len(cd_keys) == 16)

        for i in range(1, 16+1):
            self.assertTrue(i in cd_keys)
            cd_key = key.cd[i]
            for j in range(0, len(cd_key)):
                bool = cd_key[j]
                if j == expected_bits_set[i]:
                    self.assertTrue(bool)
                else:
                    self.assertFalse(bool)
                

    def test_deskey_derived_c_d_2(self):
        key = DESKey.DESKey("0101010101010110")
        # 60th bit mapped to 25th in k_plus which is in C
        expected_bits_set = (25-1,
                             24-1, 23-1, # two 1's
                             21-1, 19-1, 17-1, 15-1, 13-1, 11-1, # 6 2's
                             10-1, # 1 1
                             8-1, 6-1, 4-1, 2-1, 28-1, 26-1, # 6 2's
                             25-1 # 1 1
                             )
        self.assertTrue(len(expected_bits_set) == 17)

        for i in range(0, len(key.c)):
            derived_key = key.c[i]
            for j in range(0, len(derived_key)):
                item = derived_key[j]
                if j == expected_bits_set[i]:
                    self.assertTrue(item)
                else:
                    self.assertFalse(item)

        for derived_key in key.d:
            for item in derived_key:
                self.assertTrue(item == False)
                pass

    def test_deskey_derived_c_d(self):
        key = DESKey.DESKey("0101010101010101")
        for derived_key in key.c:
            for item in derived_key:
                self.assertTrue(item == False)
        for derived_key in key.d:
            for item in derived_key:
                self.assertTrue(item == False)

    def test_deskey_leftshift(self):
        key = DESKey.DESKey("0101010101010101")
        tuple1 = (True, False, False, False)
        actual = key.left_shift(tuple1, 1)
        expected = (False, False, False, True)
        self.assertTrue(len(actual) == len(expected))
        for i in range(0, len(expected)):
            self.assertTrue(actual[i] == expected[i])

    def test_deskey_c_d_leftshift_tuple(self):
        key = DESKey.DESKey("0101010101010101")
        self.assertTrue(len(key.C_D_LEFTSHIFT_TUPLE) == 17, msg='16 iterations + unused')

    def test_deskey_kplus_mapping_3(self):
        # http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

        tests = (
            # hex encoded key, expected true bit (25-1 indicates 25th bit, zero indexed)
            ("0101010101010110", 25-1), # 60th bit maps to 25th
            ("0101010101011001", 26-1), # 52 -> 26
            ("0101010101010801", 46-1), # 53 -> 46
            )

        for test in tests:
            keystring = test[0]
            expected_true_bit = test[1]
            key = DESKey.DESKey(keystring)
            for i in range(0, len(key.k_plus)):
                if i == expected_true_bit:
                    self.assertTrue(key.k_plus[i], msg='single bit expected true')
                else:
                    self.assertFalse(key.k_plus[i], msg='all other bits expected false')
                
    def test_deskey_kplus_mapping_2(self):
        # all zeros (only odd parity bits set)
        key = DESKey.DESKey("0101010101010101")
        for boolean in key.k_plus:
            self.assertFalse(boolean, "should be all zeros")

    def test_deskey_kplus_mapping(self):
        key = DESKey.DESKey("0E329232EA6D0D73")
        # no repeated values, no multiples of 8
        testing_list = []
        for value in key.K_PLUS_MAPPING_TUPLE:
            self.assertFalse(value in testing_list, msg='no repeated values: %s' % value)
            testing_list.append(value)
        should_not_be_there_list = [8, 16, 24, 32, 40, 48, 56, 64]
        for should_not_be_there in should_not_be_there_list:
            self.assertFalse(should_not_be_there in testing_list, msg='multiples of 8 should not be there')
        self.assertTrue(len(key.K_PLUS_MAPPING_TUPLE) == 56, msg="length 1")
        self.assertTrue(len(testing_list) == 56, msg="length 2")
        for i in range(1, 64+1):
            if (i % 8) == 0:
                self.assertFalse(i in key.K_PLUS_MAPPING_TUPLE, msg="does not contain 1")
                self.assertFalse(i in testing_list, msg="does not contain 2")
            else:
                self.assertTrue(i in key.K_PLUS_MAPPING_TUPLE, msg="contains 1")
                self.assertTrue(i in testing_list, msg="contains 2")
                pass
            pass
        pass

    PRECOMPUTED_ENCRYPTION_VALUES = [
        # [key, plaintext, ciphertext], all hex-encoded
        ['0E329232EA6D0D73', '8787878787878787', '0000000000000000'],
        ]

    def test_des_encrypt(self):
        pass

    def test_hexadecimal_bit_to_string(self):
        tests = [
            [(), ''],
            [(False, True, False, True), '5'],
            [(False, True, False, False), '4'],
            ]

        hex = Hexadecimal.Hexadecimal()
        for test in tests:
            self.assertEqual(hex.bit_tuple_to_hex_string(test[0]), test[1])

        negative_tests = [
            (True),
            (1, 0, 0, 1),
            ("True", "True", "True", "False"),
            ]

        for arg in negative_tests:
            try:
                hex.bit_tuple_to_hex_string(arg)
                self.assertTrue(False, msg='expected an exception')
            except (ValueError):
                pass

    def test_hexadecimal_string_to_bit(self):
        tests = [
            ['', ()],
            ['a', (True, False, True, False)],
            ['0A3', (False, False, False, False, True, False, True, False, False, False, True, True)],
            ]
        hex = Hexadecimal.Hexadecimal()
        for test in tests:
            self.assertEqual(hex.hex_string_to_bit_tuple(test[0]), test[1])

        negative_tests = [
            'x',
            '.',
            '8724397x',
            ]
        for arg in negative_tests:
            try:
                hex.hex_string_to_bit_tuple(arg)
                self.assertTrue(False, msg="expected an exception")
            except (ValueError):
                pass
            pass
        pass

    def test_is_hex_string(self):
        hex = Hexadecimal.Hexadecimal()
        assert hex.is_hex_string("abc") == True
        assert hex.is_hex_string("abcx") == False
        assert hex.is_hex_string("AbC0239428398432") == True
        assert hex.is_hex_string("") == True

    def test_des_encrypt_validation(self):
        happy_tests = [
            # block, key
            ["384792aaa37ABCCC", "91387ABCBCbcbcdf"]
            ]
        
        for i_unused, happy_test in enumerate(happy_tests):
            block = happy_test[0]
            key = happy_test[1]
            DES.des_encrypt(block, key)
            
        expected_exception_tests = [
            ["1", "2"],
            ["foo", "bar"],
            ]

        for i_unused, expected_exception_test in enumerate(expected_exception_tests):
            block = expected_exception_test[0]
            key = expected_exception_test[1]
            try:
                DES.des_encrypt(block, key)
                assert False, "expected an exception"
            except ValueError:
                pass
            pass
        pass
    
if __name__ == '__main__':
    unittest.main()
