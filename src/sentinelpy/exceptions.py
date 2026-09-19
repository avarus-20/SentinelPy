"""Application-level exceptions for SentinelPy."""


class SentinelPyError(Exception):
    """Base class for SentinelPy errors."""


class InvalidTargetError(SentinelPyError, ValueError):
    """Raised when a target URL is invalid."""


class NetworkError(SentinelPyError):
    """Raised when the target cannot be reached."""


class TLSError(SentinelPyError):
    """Raised when TLS negotiation or certificate verification fails."""


class RequestTimeoutError(SentinelPyError, TimeoutError):
    """Raised when an HTTP request exceeds the configured timeout."""
