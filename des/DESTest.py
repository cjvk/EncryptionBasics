import DES
import unittest

class DESTest(unittest.TestCase):

    def setUp(self):
        pass

    def test_is_hex_string(self):
        assert DES.is_hex_string("abc") == True
        assert DES.is_hex_string("abcx") == False
        assert DES.is_hex_string("AbC0239428398432") == True
        assert DES.is_hex_string("") == True

    def test_des_encrypt_validation(self):
        happy_tests = [
            ["384792aaa37ABCCC", "92387ABCDEFabcde"]
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
