from __future__ import annotations

import http.cookiejar
import json
import logging
import time
from pathlib import Path
import urllib.request
from collections.abc import Callable
from os import getenv
from typing import Any, ClassVar
from urllib.parse import urlparse

from yt_dlp.networking.common import (
    _REQUEST_HANDLERS,
    _RH_PREFERENCES,
    Request,
    RequestDirector,
    RequestHandler,
    Response,
    register_preference,
    register_rh,
)
from yt_dlp.networking.exceptions import HTTPError
from yt_dlp.utils.networking import clean_headers

LOG: logging.Logger = logging.getLogger(__name__)

if bool(getenv("FLARESOLVERR_DEBUG", "0")):
    LOG.setLevel(logging.DEBUG)
    LOG.addHandler(logging.FileHandler(Path("/tmp/yt-flaresolverr.log")))

SolverFn = Callable[[Request, Response, RequestHandler], Request | None]

_CACHE: dict[str, dict[str, Any]] = {}

FS_URL: str | None = getenv("FLARESOLVERR_URL")
FS_CLIENT_TIMEOUT: str = getenv("FLARESOLVERR_CLIENT_TIMEOUT", "60")
FS_TIMEOUT_DEFAULT: str = getenv("FLARESOLVERR_CLIENT_TIMEOUT", "60")
FS_CACHE_TTL: int = int(getenv("FLARESOLVERR_CACHE_TTL", "300"))


def _get_cached_value(domain: str) -> dict[str, Any] | None:
    if domain not in _CACHE:
        return None

    _entry: dict[str, Any] = _CACHE.get(domain)
    if time.time() - _entry["timestamp"] > FS_CACHE_TTL:
        _CACHE.pop(domain, None)
        return None

    return _entry["solution"]


def _cache_value(domain: str, solution: dict[str, Any]) -> None:
    _CACHE[domain] = {
        "solution": solution,
        "timestamp": time.time(),
    }


def cf_solver(
    request: Request, _response: Response, handler: RequestHandler
) -> Request | None:
    if not FS_URL:
        LOG.debug("FlareSolverr URL is not set.")
        return None

    parsed_endpoint = urlparse(FS_URL)
    if parsed_endpoint.scheme not in ("http", "https"):
        LOG.debug(
            f"FlareSolverr URL scheme '{parsed_endpoint.scheme}' is not supported."
        )
        return None

    if request.data is not None and request.method not in ("GET", None):
        LOG.debug(
            f"FlareSolverr does not support requests with data and method '{request.method}'."
        )
        return None

    domain: str = urlparse(request.url).hostname or ""
    method: str = request.method.lower() if isinstance(request.method, str) else "get"
    if method not in ("get", "head"):
        method = "get"

    payload: dict[str, Any] = {
        "cmd": f"request.{method}",
        "url": request.url,
        "maxTimeout": int(FS_TIMEOUT_DEFAULT * 1000),
    }

    cookiejar = handler._get_cookiejar(request)
    cookies = (
        [
            {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or urlparse(request.url).hostname or "",
                "path": cookie.path or "/",
            }
            for cookie in cookiejar
        ]
        if cookiejar
        else []
    )

    if cookies:
        payload["cookies"] = cookies

    req = urllib.request.Request(
        url=FS_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        LOG.info(
            f"Trying to solve Cloudflare challenge for '{request.url}' this may take a while..."
        )
        with urllib.request.urlopen(req, timeout=float(FS_CLIENT_TIMEOUT)) as resp:
            result: dict = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        LOG.error(f"FlareSolverr failed to solve challenge for '{request.url}': {e!s}")
        return None

    if result.get("status") != "ok":
        LOG.error(
            f"FlareSolverr failed to solve challenge for '{request.url}': {result}"
        )
        return None

    LOG.debug(f"Successfully solved Cloudflare challenge for '{request.url}'.")

    solution: dict[str, Any] = result.get("solution") or {}

    _cache_value(domain, solution)

    _make_cookiejar(solution.get("cookies"), request, handler)

    if ua := solution.get("userAgent"):
        request.headers["User-Agent"] = ua

    return request


def _make_cookiejar(cookies, request: Request, handler: RequestHandler) -> None:
    cookiejar = handler._get_cookiejar(request)
    host = urlparse(request.url).hostname or ""
    for cookie in cookies or []:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        domain = cookie.get("domain") or host
        path = cookie.get("path") or "/"
        cookiejar.set_cookie(
            http.cookiejar.Cookie(
                version=0,
                name=name,
                value=value,
                port=None,
                port_specified=False,
                domain=domain,
                domain_specified=True,
                domain_initial_dot=domain.startswith("."),
                path=path,
                path_specified=True,
                secure=bool(cookie.get("secure")),
                expires=cookie.get("expires"),
                discard=False,
                comment=None,
                comment_url=None,
                rest={},
                rfc2109=False,
            )
        )


@register_rh
class CFSolverRH(RequestHandler):
    """Request handler that intercepts Cloudflare challenges"""

    _SUPPORTED_URL_SCHEMES = ("http", "https")
    _SUPPORTED_PROXY_SCHEMES = (
        "http",
        "https",
        "socks4",
        "socks4a",
        "socks5",
        "socks5h",
    )
    solver: ClassVar[SolverFn | None] = None

    def __init__(self, *, solver: SolverFn | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._solver: SolverFn | None = solver or cf_solver
        self._fallback_director: RequestDirector | None = None

    def close(self) -> None:
        if self._fallback_director:
            self._fallback_director.close()
            self._fallback_director = None

    def _check_extensions(self, extensions) -> None:
        super()._check_extensions(extensions)
        for key in (
            "cookiejar",
            "timeout",
            "legacy_ssl",
            "keep_header_casing",
            "impersonate",
            "cf_retry",
        ):
            extensions.pop(key, None)

    def _build_fallback(self) -> RequestDirector:
        if self._fallback_director:
            return self._fallback_director

        director = RequestDirector(logger=self._logger, verbose=self.verbose)
        for handler_cls in _REQUEST_HANDLERS.values():
            if handler_cls.RH_KEY == self.RH_KEY:
                continue

            director.add_handler(
                handler_cls(
                    logger=self._logger,
                    headers=self.headers,
                    cookiejar=self.cookiejar,
                    proxies=self.proxies,
                    timeout=self.timeout,
                    source_address=self.source_address,
                    verbose=self.verbose,
                    prefer_system_certs=self.prefer_system_certs,
                    client_cert=self._client_cert,
                    verify=self.verify,
                    legacy_ssl_support=self.legacy_ssl_support,
                )
            )
        director.preferences.update(_RH_PREFERENCES)
        self._fallback_director = director
        return director

    @staticmethod
    def _is_cf_response(response: Response) -> bool:
        """
        Check if the response is a Cloudflare challenge response.

        Args:
            response (Response): The HTTP response to check.

        Returns:
            bool: True if the response is a Cloudflare challenge, False otherwise.

        """
        status: int | None = getattr(response, "status", None)
        if status not in (403, 429, 503):
            LOG.debug(f"Response status {status} is not indicative of Cloudflare.")
            return False

        headers = response.headers or {}
        server_header: str = (headers.get("Server") or "").lower()
        if "cloudflare" in server_header:
            LOG.debug("Detected Cloudflare server header.")
            return True

        cf_header_keys: tuple[str, ...] = (
            "cf-ray",
            "cf-chl-bypass",
            "cf-cache-status",
            "cf-visitor",
        )
        return any(key in headers for key in cf_header_keys)

    def _solve(self, request: Request, response: Response) -> Request | None:
        return self._solver(request, response, self) if self._solver else None

    @staticmethod
    def _mark_retry(request: Request) -> Request:
        new_request: Request = request.copy()
        new_request.extensions["cf_retry"] = True
        return new_request

    def _retry_with_clearance(
        self, request: Request, response: Response, director: RequestDirector
    ) -> Response:
        if request.extensions.get("cf_retry"):
            return response

        solved_request: Request | None = self._solve(
            self._mark_retry(request), response
        )
        if solved_request is None:
            return response

        solved_request.extensions.pop("cf_retry", None)
        clean_headers(solved_request.headers)
        response.close()
        return director.send(solved_request)

    def _send(self, request: Request) -> Response:
        LOG.debug(f"CFSolverRH handling request to {request.url}")
        director: RequestDirector = self._build_fallback()

        domain: str = urlparse(request.url).hostname or ""
        cached_solution: dict[str, Any] | None = _get_cached_value(domain)
        if cached_solution:
            LOG.debug(f"Injecting cached solution for '{domain}'")
            _make_cookiejar(cached_solution.get("cookies"), request, self)
            if ua := cached_solution.get("userAgent"):
                request.headers["User-Agent"] = ua

        try:
            response: Response = director.send(request)
        except HTTPError as error:
            if error.response and self._is_cf_response(error.response):
                return self._retry_with_clearance(request, error.response, director)
            raise

        if self._is_cf_response(response):
            return self._retry_with_clearance(request, response, director)

        return response


@register_preference(CFSolverRH)
def _prefer_cf_handler(handler: RequestHandler, _request: Request) -> int:
    return 500 if FS_URL else 0
