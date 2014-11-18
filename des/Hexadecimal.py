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
            raise ValueError
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

        return bit_tuple

