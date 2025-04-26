import ctypes
import socket
import struct
from kydns.protocol import PPrinter
from kydns.kyd_models import DNSDomain


class DNSRecord:
    def __init__(self, name: DNSDomain, rtype: int, rclass: int, ttl: int, rdlength: int, rdata: bytes, pkt: bytes, offset: int):
        self.name = name
        self.rtype = rtype          # 16bit type code
        self.rclass = rclass        # 16bit class code
        self.ttl = ttl              # 32bit uint (0 = don't cache)
        self.rdlength = rdlength    # 32bit uint length of rdata
        self.rdata = rdata          # payload bytes
        # Record context
        self.pkt = pkt              # response packet bytes
        self.offset = offset        # record offset in packet

    def __len__(self):
        return len(bytes(self))

    def __bytes__(self):
        return bytes(self.name) + struct.pack(">HHIH", self.rtype, self.rclass, self.ttl, self.rdlength) + self.rdata

    def __repr__(self):
        pp = PPrinter(section_name=self.__class__.__name__, attach=True)
        pp.add(text=f"{self.name}", bitlen=16, flex=True)
        pp.add(text=f"0x{self.rtype:04x}", bitlen=16)
        pp.add(text=f"0x{self.rclass:04x}", bitlen=16)
        pp.add(text=f"{self.ttl}", bitlen=32)
        pp.add(text=f"0x{self.rdlength:04x}", bitlen=16)
        pp.add(text=f"{self.payload()}", bitlen=32, flex=True)
        return str(pp)

    def payload(self):
        return "unknown record type"

    @classmethod
    def from_rsp(cls, rsp: bytes, index: int) -> 'DNSRecord':
        start_index = index

        domain = DNSDomain.to_domain(rsp, index)
        index += len(domain)

        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", rsp[index:index + 10])
        index += 10

        rdata = rsp[index:index + rdlength]
        rrcls = RTYPE_MAPPER.get(rtype, cls)
        return rrcls(domain, rtype, rclass, ttl, rdlength, rdata, rsp, start_index)


class ARecord(DNSRecord):
    def payload(self) -> str:
        return socket.inet_ntop(socket.AF_INET, self.rdata)


class AAAARecord(DNSRecord):
    def payload(self) -> str:
        return socket.inet_ntop(socket.AF_INET6, self.rdata)


class NSRecord(DNSRecord):
    def payload(self) -> str:
        domain = DNSDomain.to_domain(self.pkt, self.offset + len(self.name) + 10)
        return str(domain)


class OPTRecord(DNSRecord):
    def payload(self) -> str:
        return "unparsed"


RTYPE_MAPPER = {
    0x01: ARecord,
    0x1c: AAAARecord,
    0x02: NSRecord,
    0x29: OPTRecord
}
