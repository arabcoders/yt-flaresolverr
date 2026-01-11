from __future__ import annotations

import http.cookiejar
import json
import logging
import time
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

SolverFn = Callable[[Request, Response, RequestHandler], Request | None]

FS_URL = getenv("FLARESOLVERR_URL")
FS_CLIENT_TIMEOUT = getenv("FLARESOLVERR_CLIENT_TIMEOUT", "60")
FS_TIMEOUT_DEFAULT = getenv("FLARESOLVERR_CLIENT_TIMEOUT", "60")
FS_CACHE_TTL = int(getenv("FLARESOLVERR_CACHE_TTL", "300"))

# Cache structure: {domain: {"solution": dict, "timestamp": float}}
_solution_cache: dict[str, dict[str, Any]] = {}


def _get_cached_solution(domain: str) -> dict[str, Any] | None:
    """Get cached solution if it exists and is not expired."""
    if domain not in _solution_cache:
        return None
    
    cache_entry = _solution_cache[domain]
    if time.time() - cache_entry["timestamp"] > FS_CACHE_TTL:
        # Cache expired, remove it
        del _solution_cache[domain]
        return None
    
    LOG.debug(f"Using cached solution for '{domain}' (age: {int(time.time() - cache_entry['timestamp'])}s)")
    return cache_entry["solution"]


def _cache_solution(domain: str, solution: dict[str, Any]) -> None:
    """Cache a solution for the given domain."""
    _solution_cache[domain] = {
        "solution": solution,
        "timestamp": time.time(),
    }
    LOG.debug(f"Cached solution for '{domain}'")


def cf_solver(
    request: Request, _response: Response, handler: RequestHandler
) -> Request | None:
    if not FS_URL:
        return None

    parsed_endpoint = urlparse(FS_URL)
    if parsed_endpoint.scheme not in ("http", "https"):
        return None

    if request.data is not None and request.method not in ("GET", None):
        return None
    
    # Check cache first
    domain = urlparse(request.url).hostname or ""
    cached_solution = _get_cached_solution(domain)
    if cached_solution:
        _cookiejar_from_solution(cached_solution.get("cookies"), request, handler)
        if ua := cached_solution.get("userAgent"):
            request.headers["User-Agent"] = ua
        return request

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
        LOG.debug(
            f"Trying to solve Cloudflare challenge for '{request.url}' this may take a while..."
        )
        with urllib.request.urlopen(req, timeout=float(FS_CLIENT_TIMEOUT)) as resp:
            result = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        LOG.error(f"FlareSolverr failed to solve challenge for '{request.url}': {e!s}")
        return None

    if result.get("status") != "ok":
        LOG.error(
            f"FlareSolverr failed to solve challenge for '{request.url}': {result}"
        )
        return None

    LOG.debug(f"Successfully solved Cloudflare challenge for '{request.url}'.")

    solution = result.get("solution") or {}
    
    # Cache the solution
    _cache_solution(domain, solution)
    
    _cookiejar_from_solution(solution.get("cookies"), request, handler)

    if ua := solution.get("userAgent"):
        request.headers["User-Agent"] = ua

    return request


def set_cf_handler(solver: SolverFn | None = None) -> type[CFSolverRH]:
    """
    Set the Cloudflare handler.

    Args:
        solver (SolverFn | None): The solver function to use for Cloudflare challenges.
            If None, the existing solver will be used.

    Returns:
        type[CloudflareRH]: The Cloudflare request handler class.

    """
    CFSolverRH.solver = solver or CFSolverRH.solver

    return CFSolverRH


def _cookiejar_from_solution(
    cookies, request: Request, handler: RequestHandler
) -> None:
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
            return False

        headers = response.headers or {}
        server_header: str = (headers.get("Server") or "").lower()
        if "cloudflare" in server_header:
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
        director: RequestDirector = self._build_fallback()

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
    return 0 if not FS_URL else 1000
