import ctypes
from kydns.protocol import PPrinter


class DNSHeader(ctypes.BigEndianStructure):
    _fields_ = [
        ("id", ctypes.c_uint16),        # 16bit identifier
        ("qr", ctypes.c_uint8, 1),      # 1bit 0-query 1-response
        ("opcode", ctypes.c_uint8, 4),  # 4bit query type 0-standard
        ("aa", ctypes.c_uint8, 1),      # 1bit authorative answer
        ("tc", ctypes.c_uint8, 1),      # 1bit truncation
        ("rd", ctypes.c_uint8, 1),      # 1bit recursion desired
        ("ra", ctypes.c_uint8, 1),      # 1bit recursion available
        ("z", ctypes.c_uint8, 1),       # 1bit zero
        ("ad", ctypes.c_uint8, 1),      # 1bit authentic data (rfc6840)
        ("cd", ctypes.c_uint8, 1),      # 1bit checking disabled
        ("rcode", ctypes.c_uint8, 4),   # 4bit response code
        ("qdcount", ctypes.c_uint16),   # 16bit question count
        ("ancount", ctypes.c_uint16),   # 16bit answer count
        ("nscount", ctypes.c_uint16),   # 16bit count of the name server resource records
        ("arcount", ctypes.c_uint16)    # 16bit additional record count
    ]

    def __repr__(self):
        pp = PPrinter(section_name="Header")
        pp.add(text=f"0x{self.id:04x}", bitlen=16)
        pp.add(text=f"{self.qr:01b}", bitlen=1)
        pp.add(text=f"0x{self.opcode:01x}", bitlen=4)
        pp.add(text=f"{self.aa:01b}", bitlen=1)
        pp.add(text=f"{self.tc:01b}", bitlen=1)
        pp.add(text=f"{self.rd:01b}", bitlen=1)
        pp.add(text=f"{self.ra:01b}", bitlen=1)
        pp.add(text=f"{self.z:01x}", bitlen=1)
        pp.add(text=f"{self.ad:01x}", bitlen=1)
        pp.add(text=f"{self.cd:01x}", bitlen=1)
        pp.add(text=f"0x{self.rcode:01x}", bitlen=4)
        pp.add(text=f"0x{self.qdcount:04x}", bitlen=16)
        pp.add(text=f"0x{self.ancount:04x}", bitlen=16)
        pp.add(text=f"0x{self.nscount:04x}", bitlen=16)
        pp.add(text=f"0x{self.arcount:04x}", bitlen=16)
        return str(pp)
