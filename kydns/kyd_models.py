import ctypes

from kydns.kyd_exc import DNSInvalidDomain
from kydns.protocol import PPrinter

MAX_LABEL_LENGTH = 63


class QCLASS:
    IN = 1


class QTYPE:
    A = 1
    NS = 2
    AAAA = 28


class DNSDomain:
    def __init__(self, domain, raw_bytes=None):
        self.domain = domain.lower().rstrip('.')
        self.raw_bytes = raw_bytes
        self.validate()

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
            enc_len = len(enc_label).to_bytes(1, byteorder='big')
            encoded.append(enc_len + enc_label)
        return b''.join(encoded) + b'\x00'

    def validate(self) -> None:
        for label in self.domain.split('.'):
            if len(label) > MAX_LABEL_LENGTH:
                raise DNSInvalidDomain(f"Label too long: '{label}'")

    @classmethod
    def to_domain(cls, data: bytes, index: int = 0) -> tuple['DNSDomain', int]:
        start_index = index
        bytes_read = 0
        offset = False
        domain = ""

        data_len = len(data)
        while index < data_len and data[index]:
            if (data[index] >> 6) == 3:  # is offset
                index = int.from_bytes(data[index:index + 2], 'big') & 0x3f
                bytes_read += 2
                offset = True

            label_len = data[index]
            label = data[index + 1:index + 1 + label_len].decode('utf-8')
            domain += label + "."
            index += label_len + 1

            if not offset:
                bytes_read += label_len + 1

        bytes_read += 1 - offset  # non offset ends with 0x00
        return cls(domain, data[start_index:start_index + bytes_read]), bytes_read


class DNSHeader(ctypes.BigEndianStructure):
    _fields_ = [
        ("id", ctypes.c_uint16),        # 16bit identifier
        ("qr", ctypes.c_uint8, 1),      # 1bit 0-query 1-response
        ("opcode", ctypes.c_uint8, 4),  # 4bit query type 0-standard
        ("aa", ctypes.c_uint8, 1),      # 1bit authorative answer
        ("tc", ctypes.c_uint8, 1),      # 1bit truncation
        ("rd", ctypes.c_uint8, 1),      # 1bit recursion desired
        ("ra", ctypes.c_uint8, 1),      # 1bit recursion available
        ("z", ctypes.c_uint8, 3),       # 3bit zero
        ("rcode", ctypes.c_uint8, 4),   # 4bit response code
        ("qdcount", ctypes.c_uint16),   # 16bit question count
        ("ancount", ctypes.c_uint16),   # 16bit answer count
        ("nscount", ctypes.c_uint16),   # 16bit count of the name server resource records
        ("arcount", ctypes.c_uint16)    # 16bit additional record count
    ]

    def __repr__(self):
        pp = PPrinter()
        pp.add(text=f"0x{self.id:04x}", bitlen=16)
        pp.add(text=f"{self.qr:01b}", bitlen=1)
        pp.add(text=f"0x{self.opcode:01x}", bitlen=4)
        pp.add(text=f"{self.aa:01b}", bitlen=1)
        pp.add(text=f"{self.tc:01b}", bitlen=1)
        pp.add(text=f"{self.rd:01b}", bitlen=1)
        pp.add(text=f"{self.ra:01b}", bitlen=1)
        pp.add(text=f"{self.z:01x}", bitlen=3)
        pp.add(text=f"0x{self.rcode:01x}", bitlen=4)
        pp.add(text=f"0x{self.qdcount:04x}", bitlen=16)
        pp.add(text=f"0x{self.ancount:04x}", bitlen=16)
        pp.add(text=f"0x{self.nscount:04x}", bitlen=16)
        pp.add(text=f"0x{self.arcount:04x}", bitlen=16)
        return str(pp)


class DNSQuestion:
    def __init__(self, domain, qtype=QTYPE.A, qclass=QCLASS.IN):
        self.qname = domain if isinstance(domain, DNSDomain) else DNSDomain(domain)
        self.qtype = qtype
        self.qclass = qclass

    def __bytes__(self):
        q = bytes(self.qname)
        q += self.qtype.to_bytes(2, byteorder="big")
        q += self.qclass.to_bytes(2, byteorder="big")
        return q

    def __len__(self):
        return len(self.qname) + 4

    def __repr__(self):
        pp = PPrinter(attach=True)
        pp.add(text=f"{self.qname}", bitlen=16, flex=True)
        pp.add(text=f"0x{self.qtype:04x}", bitlen=16)
        pp.add(text=f"0x{self.qclass:04x}", bitlen=16)
        return str(pp)

    @classmethod
    def from_rsp(cls, rsp, index=12) -> tuple['DNSQuestion', int]:
        def to_int(data):
            return int.from_bytes(data, byteorder="big")

        domain, bytes_read = DNSDomain.to_domain(rsp, index)
        index += bytes_read
        return cls(domain=domain,
                   qtype=to_int(rsp[index:index + 2]),
                   qclass=to_int(rsp[index + 2:index + 4])), bytes_read + 4
