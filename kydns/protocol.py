class PPrinter:
    LINEWRAP = ["|", "+"]
    FLEXWRAP = ["/", "+"]
    FIELD_SEP = "|"

    def __init__(self, bits: int = 16, attach=False):
        self.bits = bits            # number of bits each line covers
        self.chars = bits * 2 - 1   # max number of characters per line
        self.curr_line = ""         # contains a line that wasn't filled by a single field
        self.free_bits = bits       # contains number of free bits remaining in such line
        self.fields = [] if attach else [self.get_top_numbers(), self.get_line_separator()]

    def get_top_numbers(self) -> str:
        """get heading numbers

        Returns:
            heading numbers lines
        """

        return "\n".join(["  " + "".join([" " * 19 + str(i + 1) for i in range(self.bits // 10)]),
                          " " + " ".join([str(i % 10) for i in range(self.bits)])])

    def get_line_separator(self) -> str:
        """get a separating line as a string

        Returns:
            separating line
        """

        return "+-" * self.bits + "+"

    def get_section_separator(self) -> str:
        """get a section separating linea as a string

         Returns:
             section separating line
         """

        return "##" * self.bits + "#"

    def is_line_full(self) -> bool:
        """check if current line is full

        Returns:
            True if current line is full
        """

        return self.free_bits == 0

    def is_new_line(self) -> bool:
        """check if current line is empty

        Returns:
            True if current line is empty
        """

        return self.free_bits == self.bits

    def can_fill_line(self, bitlen: int) -> bool:
        """check if field size may fill a single line fully

        Args:
            bitlen:         field length in bits

        Returns:
            True if field length is exactly total bits per line
        """

        return bitlen == self.bits

    def can_fill_lines(self, bitlen: int) -> bool:
        """check if field size may fill multiple lines fully

        Args:
            bitlen:         field length in bits

        Returns:
            True if field length is a multiple of total bits per line
        """

        return bitlen % self.bits == 0

    def add_singleline(self, text: str, flex: bool) -> None:
        """add a line that fits exactly on a single line

        Args:
            text:           field text
            flex:           flexible field len [default: False]
        """

        self.fields.append(self.wrap_line(self.center_text(text, self.bits), flex=flex))

    def add_multiline(self, text: str, bitlen: int, flex: bool) -> None:
        """add a line that fits exactly in multiple lines

        Args:
            text:           field text
            bitlen:         field length in bits
            flex:           flexible field len [default: False]
        """

        total_lines = (bitlen // self.bits) * 2 - 1
        mid_ind = total_lines // 2
        for i in range(total_lines):
            self.fields.append(self.wrap_line(self.center_text(text if i == mid_ind else "", self.bits),
                                              multiline_ind=i, flex=flex))

    def add_multifield_line(self) -> None:
        """add a line that's from multiple fields
        1. add current line
        2. reset free bits to max (self.bits)
        3. reset current line to empty
        """

        self.fields.append(self.wrap_line(self.curr_line))
        self.free_bits = self.bits
        self.curr_line = ""

    def add_field(self, text: str, bitlen: int) -> None:
        """adds a field that doesn't cover a full line, to the current line

        Args:
            text:           field text
            bitlen:         field length in bits
        """

        self.free_bits -= bitlen
        self.curr_line += self.center_text(text, bitlen)

    def append(self, text: str, bitlen: int) -> None:
        """append a field that doesn't cover a full line

        Args:
            text:           field text
            bitlen:         field length in bits

        Raises:
            NotImplementedError: if field is size is not supported.
                                 ie can't fit in one line
        """

        if bitlen <= self.free_bits:
            self.add_field(text, bitlen)
        else:
            raise NotImplementedError

        if self.is_line_full():
            self.add_multifield_line()
        else:
            self.curr_line = self.wrap_field(self.curr_line)

    def add(self, text: str, bitlen: int, flex: bool = False) -> None:
        """add a field to the protocol struct

        Args:
            text:           field text
            bitlen:         field length in bits
            flex:           flexible field len [default: False]

        Raises:
            NotImplementedError: if field is size is not supported.
                                 ie doesn't cover full line,
                                 nor adds up to full line
        """

        if self.is_new_line():
            if self.can_fill_line(bitlen):
                self.add_singleline(text, flex)
            elif self.can_fill_lines(bitlen):
                self.add_multiline(text, bitlen, flex)
            elif bitlen < self.bits:
                self.append(text, bitlen)
            else:
                raise NotImplementedError
        else:
            self.append(text, bitlen)

        if self.is_new_line():
            self.fields.append(self.get_line_separator())

    def __repr__(self):
        return "\n".join(self.fields) + "<--" + "\n"

    def center_text(self, text: str, bitlen: int) -> str:
        charlen = self.bitlen_to_charlen(bitlen)
        if len(text) > charlen:
            text = text[:charlen - 1] + "."
        return str.center(text, charlen)

    @staticmethod
    def wrap_field(field: str):
        """wrap a field by adding field separator

        Args:
            field:          str representing a field in line

        Returns:
            string of field appended with field separator
        """

        return field + PPrinter.FIELD_SEP

    @staticmethod
    def wrap_line(line: str, multiline_ind: int = 0, flex: bool = False) -> str:
        """once a line is ready to be printed, add starting and ending chars

        Args:
            line:           str representing a line to print
            multiline_ind:  line index in multiline fields [default: 0]
            flex:           flexible field len [default: False]

        Returns:
            str of ready for printing line
        """

        char = PPrinter.FLEXWRAP[multiline_ind % 2] if flex else PPrinter.LINEWRAP[multiline_ind % 2]
        return char + line + char

    @staticmethod
    def bitlen_to_charlen(bitlen: int) -> int:
        """get number of characters that covers the given number of bits

        Args:
            bitlen:         num bits

        Returns:
            num characters
        """

        return bitlen * 2 - 1
