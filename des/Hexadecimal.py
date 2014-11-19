import re

class Hexadecimal():

    def is_hex_string(self, s):
        m = re.search('^[0-9a-fA-F]*$', s)
        return not m is None

    # and, or, ^

    MAPPING = {
        # only uses uppercase hex
        '0' : (False, False, False, False),
        '1' : (False, False, False, True ),
        '2' : (False, False, True , False),
        '3' : (False, False, True , True ),
        '4' : (False, True , False, False),
        '5' : (False, True , False, True ),
        '6' : (False, True , True , False),
        '7' : (False, True , True , True ),
        '8' : (True , False, False, False),
        '9' : (True , False, False, True ),
        'A' : (True , False, True , False),
        'B' : (True , False, True , True ),
        'C' : (True , True , False, False),
        'D' : (True , True , False, True ),
        'E' : (True , True , True , False),
        'F' : (True , True , True , True ),
        }

    INT_TO_HEX_DIGIT = {
        0 : '0',
        1 : '1',
        2 : '2',
        3 : '3',
        4 : '4',
        5 : '5',
        6 : '6',
        7 : '7',
        8 : '8',
        9 : '9',
        10: 'A',
        11: 'B',
        12: 'C',
        13: 'D',
        14: 'E',
        15: 'F'
        }

    HEX_DIGIT_TO_INT = {
        '0' : 0,
        '1' : 1,
        '2' : 2,
        '3' : 3,
        '4' : 4,
        '5' : 5,
        '6' : 6,
        '7' : 7,
        '8' : 8,
        '9' : 9,
        'A' : 10,
        'a' : 10,
        'B' : 11,
        'b' : 11,
        'C' : 12,
        'c' : 12,
        'D' : 13,
        'd' : 13,
        'E' : 14,
        'e' : 14,
        'F' : 15,
        'f' : 15
        }


    def bit_tuple_to_hex_string(self, bit_tuple):
        # validation
        if not isinstance(bit_tuple, tuple):
            raise ValueError
        for should_be_a_bool in bit_tuple:
            if not isinstance(should_be_a_bool, bool):
                raise ValueError
        length = len(bit_tuple)
        newlength = (length / 4) * 4
        if not length == newlength:
            raise ValueError("Length=%s, newlength=%s" % (str(length), str(newlength)))
        hex_string = ''

        while len(bit_tuple) > 0:
            bite = bit_tuple[0:4]
            bit_tuple = bit_tuple[4:]
            for k in self.MAPPING.keys():
                if self.MAPPING[k] == bite:
                    hex_string = hex_string + k
                    break
        return hex_string

    def hex_string_to_bit_tuple(self, hex_string):
        if not self.is_hex_string(hex_string):
            raise ValueError
        hex_string_uppercase = hex_string.upper()
        bit_tuple = ()

        for i in range(0, len(hex_string_uppercase)):
            bit_tuple = bit_tuple + self.MAPPING[hex_string_uppercase[i]]

        assert(type(bit_tuple) is tuple)
        return bit_tuple

