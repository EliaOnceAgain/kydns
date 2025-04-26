import struct
from kydns.kyd_exc import DNSInvalidDomain


class DNSDomain:
    def __init__(self, domain, raw_bytes=None):
        self.domain = domain.lower().rstrip('.')
        self.raw_bytes = raw_bytes

    def __len__(self):
        return len(self.__bytes__())

    def __repr__(self):
        return self.domain

    def __bytes__(self) -> bytes:
        if self.raw_bytes:
            return self.raw_bytes
        encoded = []
        for label in self.domain.split('.'):
            enc_label = label.encode('utf-8')
            encoded.append(struct.pack(">b", len(enc_label)) + enc_label)
        return b''.join(encoded) + b'\x00'

    @classmethod
    def to_domain(cls, data: bytes, index: int = 0) -> 'DNSDomain':
        start_index = index
        bytes_read = 0
        offset = False
        domain = ""

        data_len = len(data)
        while index < data_len and data[index]:
            if (data[index] >> 6) == 3:  # is offset
                index = struct.unpack(">H", data[index:index + 2])[0] & 0x3f
                bytes_read += 2
                offset = True

            label_len = data[index]
            label = data[index + 1:index + 1 + label_len].decode('utf-8')
            domain += label + "."
            index += label_len + 1

            if not offset:
                bytes_read += label_len + 1

        bytes_read += 1 - offset  # non offset ends with 0x00
        return cls(domain, data[start_index:start_index + bytes_read])
