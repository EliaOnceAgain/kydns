class DNSError(Exception):
    pass


# Request Errors

class DNSInvalidDomain(DNSError):
    pass


# Response Errors

class DNSFormatError(DNSError):
    pass


class DNSServerFailure(DNSError):
    pass


class DNSNameError(DNSError):
    pass


class DNSNotImplemented(DNSError):
    pass


class DNSRefused(DNSError):
    pass


class DNSResponseTimeout(DNSError):
    pass
