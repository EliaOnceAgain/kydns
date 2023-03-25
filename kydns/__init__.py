__version__ = "0.1.4"

import secrets
import socket

from kydns.kyd_exc import *
from kydns.kyd_models import DNSHeader, DNSQuestion
from kydns.kyd_records import DNSRecord

DNS_HEADER_LEN = 12


class Request:
    def __init__(self, domain, qtype=1, qclass=1, id=None,
                 qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, z=0, rcode=0,
                 qdcount=1, ancount=0, nscount=0, arcount=0):
        self.header = DNSHeader(id=id or int(secrets.token_hex(2), 16),
                                qr=qr, opcode=opcode, aa=aa, tc=tc, rd=rd, ra=ra, z=z, rcode=rcode,
                                qdcount=qdcount, ancount=ancount, nscount=nscount, arcount=arcount)
        self.question = DNSQuestion(domain, qtype, qclass)

    def __repr__(self):
        return str(self.header) + str(self.question)

    def __bytes__(self):
        return bytes(self.header) + bytes(self.question)

    def send(self, addr, timeout: int = 1) -> 'Response':
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(bytes(self), addr)
            try:
                data, server = sock.recvfrom(4096)
            except socket.timeout:
                raise DNSResponseTimeout(f"Timed out after waiting for response from {addr} after {timeout}s")
        finally:
            sock.close()
        return self.to_rsp(rsp=data, rsp_server=server)

    def to_rsp(self, rsp: bytes, rsp_server: tuple = None) -> 'Response':
        obj = Response(rsp_server)
        obj.header = DNSHeader.from_buffer_copy(rsp[:DNS_HEADER_LEN])
        self.raise_on_err(obj.header)
        obj.question, bytes_read = DNSQuestion.from_rsp(rsp)
        index = DNS_HEADER_LEN + bytes_read
        for _ in range(obj.header.ancount):
            record, bytes_read = DNSRecord.from_rsp(obj.question.qtype, rsp, index)
            obj.add_record(record)
            index += bytes_read
        return obj

    def raise_on_err(self, rsp_header) -> None:
        if self.header.id != rsp_header.id:
            raise DNSError(f"Response ID does not match: {self.header.id} != {rsp_header.id}")
        if rsp_header.rcode:
            if rsp_header.rcode == 1:
                raise DNSFormatError(f"Name server unable to interpret the query")
            if rsp_header.rcode == 2:
                raise DNSServerFailure()
            if rsp_header.rcode == 3:
                raise DNSNameError("Requested domain name does not exist")
            if rsp_header.rcode == 4:
                raise DNSNotImplemented("The name server does not support the requested query type")
            if rsp_header.rcode == 5:
                raise DNSRefused("The name server refuses to perform the specified operation")
        if rsp_header.qdcount > 1:
            raise DNSError(f"Responses with more than 1 question are unsupported")


class Response:
    def __init__(self, rsp_server: tuple = None):
        self.server = rsp_server or "NA"
        self.header = None
        self.question = None
        self.records = []

    def __repr__(self):
        return str(self.header) + str(self.question) + "".join(str(r) for r in self.records)

    def __bytes__(self):
        return bytes(self.header) + bytes(self.question) + b"".join(bytes(r) for r in self.records)

    def add_record(self, record):
        self.records.append(record)
