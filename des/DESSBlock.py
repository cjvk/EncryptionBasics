class DESSBlock:
    """
    represents the 8 S-blocks of DES

    For more information:
    http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
    """
    def __init__(self, s_number = None):
        self.s_number = s_number
        self.validate()
        self.derived_data()

    def validate(self):
        if self.s_number is None:
            raise ValueError("s number is not optional")
        assert(self.s_number >= 1 and self.s_number <= 8)

    def derived_data(self):
        self.lookup_array = self.ALL_S_BLOCKS[self.s_number]
        pass

    def s_transform(self, input):
        assert(len(input) == 6)
        # FIXME
        return [False, True, False, True]

    ALL_S_BLOCKS = {
        1 : None,
        2 : None,
        3 : None,
        4 : None,
        5 : None,
        6 : None,
        7 : None,
        8 : None
        }
