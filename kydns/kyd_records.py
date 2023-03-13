import socket

from kydns.protocol import PPrinter
from kydns.kyd_models import DNSDomain, QTYPE, QCLASS


class DNSRecord:
    def __init__(self,
                 name: DNSDomain,
                 rtype: int = QTYPE.A,      # 16bit type code
                 rclass: int = QCLASS.IN,   # 16bit class code
                 ttl: int = 0,              # 32bit int, valid for, 0=don't cache
                 rdlength: int = 0,         # 32bit uint, rdata length in bytes
                 rdata: bytes = b"0000",    # answer, varies according to rtype and rclass
                 ):
        self.name = name
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdlength = rdlength
        self.rdata = rdata

    def __bytes__(self):
        ans = bytes(self.name)
        ans += self.rtype.to_bytes(2, byteorder="big")
        ans += self.rclass.to_bytes(2, byteorder="big")
        ans += self.ttl.to_bytes(4, byteorder="big")
        ans += self.rdlength.to_bytes(2, byteorder="big")
        ans += self.rdata
        return ans

    def __repr__(self):
        pp = PPrinter(attach=True)
        pp.add(text=f"{self.name}", bitlen=16, flex=not self.name.offset)
        pp.add(text=f"0x{self.rtype:04x}", bitlen=16)
        pp.add(text=f"0x{self.rclass:04x}", bitlen=16)
        pp.add(text=f"{self.ttl}", bitlen=32)
        pp.add(text=f"0x{self.rdlength:04x}", bitlen=16)
        pp.add(text=f"{self.ans}", bitlen=32, flex=True)
        return str(pp)

    @property
    def ans(self):
        return self.rdata

    @classmethod
    def from_rsp(cls, rtype: int, rsp: bytes, index: int):
        domain = DNSDomain.to_domain(rsp, index)
        index += len(domain)
        rdlength = to_int(rsp[index + 8:index + 10])
        return RTYPE_MAPPER.get(rtype)(name=domain,
                                       rtype=to_int(rsp[index:index + 2]),
                                       rclass=to_int(rsp[index + 2:index + 4]),
                                       ttl=to_int(rsp[index + 4:index + 8]),
                                       rdlength=rdlength,
                                       rdata=rsp[index + 10:index + 10 + rdlength])


class ARecord(DNSRecord):
    @property
    def ans(self):
        return socket.inet_ntop(socket.AF_INET, self.rdata)


class AAAARecord(DNSRecord):
    @property
    def ans(self):
        return socket.inet_ntop(socket.AF_INET6, self.rdata)


def to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")


RTYPE_MAPPER = {
    QTYPE.A: ARecord,
    QTYPE.AAAA: AAAARecord,
}
