from kydns import Request
from kydns.kyd_exc import *
from kydns.kyd_models import QTYPE

TEST_DOMAIN_NAME_CORRECT = "example.com"
TEST_DOMAIN_NAME_WRONG = "exmaple.com"
TEST_DOMAIN_IP4 = "96.7.128.198"
TEST_DOMAIN_IP6 = "2600:1406:3a00:21::173e:2e65"
TEST_SERVER = ("1.1.1.1", 53)


def test_request_ipv4():
    req = Request(domain=TEST_DOMAIN_NAME_CORRECT)
    rsp = req.send(TEST_SERVER)
    assert any(rr.ans == TEST_DOMAIN_IP4 for rr in rsp.records), f"response missing expected ipv4: {TEST_DOMAIN_IP4}"


def test_request_ipv6():
    req = Request(domain=TEST_DOMAIN_NAME_CORRECT, qtype=QTYPE.AAAA)
    rsp = req.send(TEST_SERVER)
    assert any(rr.ans == TEST_DOMAIN_IP6 for rr in rsp.records), f"response missing expected ipv6: {TEST_DOMAIN_IP6}"


def test_request_ns():
    req = Request(domain=TEST_DOMAIN_NAME_CORRECT, qtype=QTYPE.NS)
    rsp = req.send(TEST_SERVER)
    assert rsp and rsp.header.ancount > 0


def test_response_rebuild():
    req = Request(domain=TEST_DOMAIN_NAME_CORRECT, qtype=QTYPE.NS)
    rsp = req.send(TEST_SERVER)
    rsp2 = req.to_rsp(bytes(rsp))
    assert bytes(rsp) == bytes(rsp2)
    assert str(rsp) == str(rsp2)


def test_request_wrong():
    req = Request(domain=TEST_DOMAIN_NAME_WRONG)
    rsp = req.send(TEST_SERVER)
    assert rsp.records[0].rdata != TEST_DOMAIN_IP4, f"response: {rsp.records[0].rdata},  expected: {TEST_DOMAIN_IP4}"


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


test_request_ipv4()
test_request_ipv6()
test_request_ns()
test_response_rebuild()
test_request_wrong()
test_invalid_domain()
test_nonexisting_domain()
