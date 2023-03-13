from kydns import Request
from kydns.kyd_exc import *

TEST_DOMAIN_NAME_CORRECT = "example.com"
TEST_DOMAIN_NAME_WRONG = "exmaple.com"
TEST_DOMAIN_IP4 = "93.184.216.34"
TEST_DOMAIN_IP6 = "2606:2800:220:1:248:1893:25c8:1946"
TEST_SERVER = ("100.93.66.103", 53)


def test_request_ipv4():
    req = Request(domain=TEST_DOMAIN_NAME_CORRECT)
    rsp = req.send(TEST_SERVER)
    assert rsp.record.ans == TEST_DOMAIN_IP4, f"response: {rsp.record.ans},  expected: {TEST_DOMAIN_IP4}"


def test_request_ipv6():
    req = Request(domain=TEST_DOMAIN_NAME_CORRECT, qtype=28)
    rsp = req.send(TEST_SERVER)
    assert rsp.record.ans == TEST_DOMAIN_IP6, f"response: {rsp.record.ans},  expected: {TEST_DOMAIN_IP4}"


def test_request_wrong():
    req = Request(domain=TEST_DOMAIN_NAME_WRONG)
    rsp = req.send(TEST_SERVER)
    assert rsp.record.rdata != TEST_DOMAIN_IP4, f"response: {rsp.record.rdata},  expected: {TEST_DOMAIN_IP4}"


def test_invalid_domain():
    success = 0
    try:
        req = Request(domain="abcdefghikabcdefghikabcdefghikabcdefghikabcdefghikabcdefghikabcdefghik.com")
        req.send(TEST_SERVER)
    except DNSInvalidDomain:
        success = 1
    assert success, f"expected invalid domain"


def test_nonexisting_domain():
    success = 0
    req = Request(domain="abcdefghikabcdefghikabcdefghc.nothing")
    try:
        req.send(TEST_SERVER)
    except DNSNameError:
        success = 1
    assert success, f"expected domain not found"


def test_header_qr():
    """set request header qr to 1, as if it was a response.
    the dns server is expected to ignore the request
    *server implementation dependent*"""

    success = 0
    req = Request(domain=TEST_DOMAIN_NAME_CORRECT)
    req.header.qr = 1
    try:
        req.send(TEST_SERVER)
    except DNSResponseTimeout:
        success = 1
    assert success, f"expected invalid domain"


def test_header_opcode():
    req = Request(domain=TEST_DOMAIN_IP4)
    req.header.opcode = 1
    success = False
    try:
        req.send(TEST_SERVER)
    except DNSNotImplemented:
        success = True
    assert success


test_request_ipv4()
test_request_ipv6()
test_request_wrong()
test_invalid_domain()
test_nonexisting_domain()
test_header_qr()
test_header_opcode()
