"""
Flask-RealIP
-----------
A Flask extension that obtains the real IP address of clients behind proxies.
"""

import re
from typing import Optional, List
from flask import Flask, current_app
from netaddr import IPAddress, AddrFormatError


class RealIP:
    """Get the real IP address of clients behind proxies for Flask apps."""

    def __init__(
        self,
        app: Optional[Flask] = None,
        trusted_proxies: Optional[List[str]] = None,
        forwarded_headers: Optional[List[str]] = None,
        proxied_only: bool = True,
    ):
        self.app = app
        self.defaults = {
            "trusted_proxies": trusted_proxies or ["127.0.0.1", "::1"],
            "forwarded_headers": forwarded_headers
            or [
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_REAL_IP",
                "HTTP_X_FORWARDED",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED",
            ],
            "proxied_only": proxied_only,
        }

        if app is not None:
            self.init_app(app)

    @property
    def trusted_proxies(self) -> List[str]:
        """Get the trusted proxies from the Flask app's config."""
        return current_app.config["REAL_IP_TRUSTED_PROXIES"]

    @property
    def forwarded_headers(self) -> List[str]:
        """Get the forwarded headers from the Flask app's config."""
        return current_app.config["REAL_IP_FORWARDED_HEADERS"]

    @property
    def proxied_only(self) -> bool:
        """Get the proxied only flag from the Flask app's config."""
        return current_app.config["REAL_IP_PROXIED_ONLY"]

    def init_app(self, app: Flask) -> None:
        """Configure the specified Flask app to use real IP middleware."""
        app.config.setdefault(
            "REAL_IP_TRUSTED_PROXIES", self.defaults["trusted_proxies"]
        )
        app.config.setdefault(
            "REAL_IP_FORWARDED_HEADERS", self.defaults["forwarded_headers"]
        )
        app.config.setdefault("REAL_IP_PROXIED_ONLY", self.defaults["proxied_only"])

        parent = self

        class RealIPRequest(app.request_class):
            """
            Custom request class that uses the real IP middleware.
            """

            @property
            def remote_addr(self):
                """
                Get the real remote address, handling proxies and IPv6 conversions.

                Returns:
                    str or None: The real IP address or None if invalid/non-routable
                """
                remote_ip = self.environ.get("REMOTE_ADDR")

                if parent.proxied_only and remote_ip not in parent.trusted_proxies:
                    return remote_ip

                for header in parent.forwarded_headers:
                    forwarded_ip = self.environ.get(header)
                    if forwarded_ip:
                        if "," in forwarded_ip:
                            forwarded_ip = forwarded_ip.split(",")[0].strip()

                        remote_ip = parent._clean_ip(forwarded_ip)
                        break

                if not remote_ip:
                    return None

                return parent._format_ip(remote_ip)

            @remote_addr.setter
            def remote_addr(self, _value: str) -> None:
                """Setter for remote_addr to handle Werkzeug's initialization."""

        app.request_class = RealIPRequest

    def _clean_ip(self, ip_str: str) -> str:
        """
        Clean up an IP string, removing brackets, port numbers, etc.
        """
        if ip_str.startswith("["):
            match = re.match(r"^\[([^\]]+)\](?::\d+)?$", ip_str)
            if match:
                return match.group(1)
        else:
            colon_count = ip_str.count(":")
            if colon_count == 1 and "::" not in ip_str:
                return ip_str.split(":")[0]

        return ip_str

    def _format_ip(self, ip_str: str) -> Optional[str]:
        """
        Format and validate an IP address, returning None for invalid or non-routable IPs.
        """
        try:
            ip = IPAddress(ip_str)

            if ip.version == 6:
                if ip.is_ipv4_mapped() or ip.is_ipv4_compat():
                    ipv4_addr = str(ip.ipv4())
                    if self._is_valid_routable_ip(ipv4_addr):
                        return ipv4_addr
                    return None

            if self._is_valid_routable_ip(str(ip)):
                return str(ip.format(dialect=None))
            return None

        except (AddrFormatError, ValueError):
            return None

    def _is_valid_routable_ip(self, ip_str: str) -> bool:
        """
        Check if an IP address string is valid and routable.

        Args:
            ip_str: IP address string to validate

        Returns:
            bool: True if valid and routable, False otherwise
        """
        try:
            ip = IPAddress(ip_str)

            is_private = (ip.version == 4 and ip.is_ipv4_private_use()) or (
                ip.version == 6 and ip.is_ipv6_unique_local()
            )

            return not (
                is_private
                or ip.is_loopback()
                or ip.is_multicast()
                or ip.is_reserved()
                or ip.is_link_local()
            )
        except (AddrFormatError, ValueError):
            return False
