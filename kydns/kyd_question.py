import struct
from kydns.kyd_models import DNSDomain
from kydns.protocol import PPrinter

class QCLASS:
    IN = 1


class QTYPE:
    A = 1
    NS = 2
    AAAA = 28


class DNSQuestion:
    def __init__(self, domain, qtype=QTYPE.A, qclass=QCLASS.IN):
        self.qname = domain if isinstance(domain, DNSDomain) else DNSDomain(domain)
        self.qtype = qtype
        self.qclass = qclass

    def __bytes__(self):
        return bytes(self.qname) + struct.pack(">HH", self.qtype, self.qclass)

    def __len__(self):
        return len(bytes(self))

    def __repr__(self):
        pp = PPrinter(section_name="Question", attach=True)
        pp.add(text=f"{self.qname}", bitlen=16, flex=True)
        pp.add(text=f"0x{self.qtype:04x}", bitlen=16)
        pp.add(text=f"0x{self.qclass:04x}", bitlen=16)
        return str(pp)

    @classmethod
    def from_rsp(cls, rsp, index=12) -> 'DNSQuestion':
        domain = DNSDomain.to_domain(rsp, index)
        index += len(domain)
        qtype, qclass = struct.unpack(">HH", rsp[index:index + 4])
        return cls(domain=domain, qtype=qtype, qclass=qclass)
