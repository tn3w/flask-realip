"""Flask-RealIP: get the real client IP behind proxies."""

import re
from typing import List, Optional

from flask import Flask
from netaddr import AddrFormatError, IPAddress

DEFAULT_HEADERS = [
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_REAL_IP",
    "HTTP_X_FORWARDED",
    "HTTP_FORWARDED_FOR",
    "HTTP_FORWARDED",
]


def _strip_port(value: str) -> str:
    match = re.fullmatch(r"\[([^\]]+)\](?::\d+)?", value)
    if match:
        return match.group(1)
    return value.split(":")[0] if value.count(":") == 1 else value


def _parse(value: str) -> Optional[IPAddress]:
    """Parse a routable IP, unwrapping IPv4-mapped/compatible IPv6."""
    try:
        ip = IPAddress(_strip_port(value.strip()))
    except (AddrFormatError, ValueError):
        return None
    if ip.version == 6 and (ip.is_ipv4_mapped() or ip.is_ipv4_compat()):
        ip = ip.ipv4()
    private = (
        ip.is_ipv4_private_use() if ip.version == 4 else ip.is_ipv6_unique_local()
    )
    if (
        private
        or ip.is_loopback()
        or ip.is_multicast()
        or ip.is_reserved()
        or ip.is_link_local()
    ):
        return None
    return ip


class RealIP:
    """Make request.remote_addr return the real client IP behind proxies."""

    def __init__(
        self,
        app: Optional[Flask] = None,
        trusted_proxies: Optional[List[str]] = None,
        forwarded_headers: Optional[List[str]] = None,
        proxied_only: bool = True,
        prefer_ipv4: bool = True,
    ):
        self.defaults = {
            "REAL_IP_TRUSTED_PROXIES": trusted_proxies or ["127.0.0.1", "::1"],
            "REAL_IP_FORWARDED_HEADERS": forwarded_headers or list(DEFAULT_HEADERS),
            "REAL_IP_PROXIED_ONLY": proxied_only,
            "REAL_IP_PREFER_IPV4": prefer_ipv4,  # IPv4 is always preferred
        }
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        for key, value in self.defaults.items():
            app.config.setdefault(key, value)
        app.extensions["realip"] = self

        class RealIPRequest(app.request_class):  # type: ignore[misc]
            @property
            def remote_addr(self) -> Optional[str]:
                remote: Optional[str] = self.environ.get("REMOTE_ADDR")
                config = app.config
                if (
                    config["REAL_IP_PROXIED_ONLY"]
                    and remote not in config["REAL_IP_TRUSTED_PROXIES"]
                ):
                    return remote

                headers = config["REAL_IP_FORWARDED_HEADERS"]
                value = next((v for h in headers if (v := self.environ.get(h))), None)
                if value is None:
                    return remote

                ips = [ip for ip in map(_parse, value.split(",")) if ip]
                ips.sort(key=lambda ip: ip.version)
                return str(ips[0]) if ips else None

            @remote_addr.setter
            def remote_addr(self, _value: str) -> None:
                """Ignore Werkzeug's own assignment."""

        app.request_class = RealIPRequest
