"""
Private HTTP client for SentinelPy.

Not part of the public scan API until v0.2.0b orchestration is added.
"""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from typing import Any

from urllib.request import HTTPRedirectHandler, Request, build_opener

from sentinelpy._version import __version__
from sentinelpy.exceptions import NetworkError, RequestTimeoutError, TLSError
from sentinelpy.http.url import normalize_url
from sentinelpy.models.http_meta import HttpResponse, RedirectHop
from sentinelpy.redaction.url import redact_url

DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = f"SentinelPy/{__version__}"


@dataclass(frozen=True, slots=True)
class FetchOptions:
    """Options for a single HTTP GET request."""

    timeout: float = DEFAULT_TIMEOUT
    user_agent: str = DEFAULT_USER_AGENT
    follow_redirects: bool = True


class _RecordingRedirectHandler(HTTPRedirectHandler):
    """Record redirect hops using redacted URLs."""

    def __init__(self) -> None:
        self.hops: list[RedirectHop] = []

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        self.hops.append(
            RedirectHop(
                from_url=redact_url(req.full_url),
                to_url=redact_url(newurl),
                status=code,
            )
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Disable automatic redirect following."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        return None


def fetch(target: str, *, options: FetchOptions | None = None) -> HttpResponse:
    """
    Perform one HTTP GET and return private response metadata.

    Raises InvalidTargetError, RequestTimeoutError, NetworkError, or TLSError.
    """

    opts = options or FetchOptions()
    normalized = normalize_url(target)
    redirect_handler = _RecordingRedirectHandler()
    if opts.follow_redirects:
        opener = build_opener(redirect_handler)
    else:
        opener = build_opener(_NoRedirectHandler())
    request = Request(
        normalized,
        headers={"User-Agent": opts.user_agent},
        method="GET",
    )

    started = time.perf_counter()

    try:
        with opener.open(request, timeout=opts.timeout) as response:
            elapsed_ms = (time.perf_counter() - started) * 1000
            return HttpResponse(
                target_url=redact_url(normalized),
                final_url=redact_url(response.geturl()),
                status=response.status,
                headers=dict(response.headers.items()),
                redirects=tuple(redirect_handler.hops),
                elapsed_ms=elapsed_ms,
            )

    except HTTPError as error:
        elapsed_ms = (time.perf_counter() - started) * 1000
        return HttpResponse(
            target_url=redact_url(normalized),
            final_url=redact_url(error.geturl()),
            status=error.code,
            headers=dict(error.headers.items()),
            redirects=tuple(redirect_handler.hops),
            elapsed_ms=elapsed_ms,
        )

    except TimeoutError as error:
        raise RequestTimeoutError("Request timed out.") from error

    except URLError as error:
        reason = error.reason
        if isinstance(reason, TimeoutError):
            raise RequestTimeoutError("Request timed out.") from error
        if isinstance(reason, ssl.SSLError):
            raise TLSError(
                "TLS handshake or certificate verification failed."
            ) from error
        raise NetworkError("Unable to reach the target.") from error
