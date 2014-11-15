import DES
import unittest

class DESTest(unittest.TestCase):

    def setUp(self):
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

        hex = DES.Hexadecimal()
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
        hex = DES.Hexadecimal()
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
        validator = DES.DESEncryptValidator()
        assert validator.is_hex_string("abc") == True
        assert validator.is_hex_string("abcx") == False
        assert validator.is_hex_string("AbC0239428398432") == True
        assert validator.is_hex_string("") == True

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
