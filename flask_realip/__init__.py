"""
Flask-RealIP
-----------
A Flask extension that obtains the real IP address of clients behind proxies.
"""

__version__ = "1.0.1"

from .real_ip import RealIP

__all__ = ["RealIP"]
