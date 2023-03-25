[![PyPI Version][pypi-image]][pypi-url]
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[pypi-image]: https://img.shields.io/pypi/v/kydns
[pypi-url]: https://pypi.org/project/kydns

# KYDNS

KYDNS (Know Your DNS) is a simple DNS client library written in Python 3. 
It allows sending DNS queries for A, AAAA, and NS records, easily modify any of the DNS packet fields, and provides an ASCII representation of the DNS packets.  
The library is designed to be easy to use and can be used for learning, testing, or other purposes.

## Installation

KYDNS uses Python 3 standard libs and has no 3rd party dependencies. Install using pip:
```shell
pip install kydns
```
Or git clone:
```shell
git clone https://github.com/eliaonceagain/kydns.git
cd kydns/
pip install .
```

## Usage

Send a DNS query for the A record of `google.com` and return the response

```python
from kydns import Request

req = Request("google.com")
rsp = req.send(("1.1.1.1", 53))
```
```text
>>> rsp
                     1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x382a            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|  0x0  |0|0|1|1|  0  |  0x0  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0000            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0000            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--
/           google.com          /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--
/           google.com          /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |
+               80              +
|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0004            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                               /
+         172.217.18.14         +
/                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--
```

### Set Query Fields

KYDNS also allows you to easily modify any of the DNS packet fields before sending the query. 
Here is an example of how to set the DNS request ID:

```python
from kydns import Request

req = Request('google.com')  # or Request('google.com', id=0x1234)
req.header.id = 0x1234  
rsp = req.send(("1.1.1.1", 53))
assert req.header.id == rsp.header.id == 0x1234
```
```text
>>> req.header
                     1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x1234            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|  0x0  |0|0|1|0|  0  |  0x0  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0000            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0000            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0000            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--

>>> rsp.header
                     1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x1234            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|  0x0  |0|0|1|1|  0  |  0x0  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0001            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0000            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             0x0000            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<--
```

## License

KYDNS is licensed under the MIT license. See the LICENSE file for more details.
