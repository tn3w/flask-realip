# Flask-RealIP

A Flask extension that obtains the real IP address of clients behind proxies.

## Install

```bash
pip install flask-realip
```

## Usage

```python
from flask import Flask, request
from flask_realip import RealIP

app = Flask(__name__)
RealIP(app)  # or RealIP().init_app(app)

@app.route("/")
def index():
    return request.remote_addr  # real client IP
```

Options: constructor args, or Flask config (`REAL_IP_<NAME>`).

- `trusted_proxies` (`REAL_IP_TRUSTED_PROXIES`): exact proxy IPs allowed to set forwarding headers. Default `['127.0.0.1', '::1']`
- `forwarded_headers` (`REAL_IP_FORWARDED_HEADERS`): WSGI environ keys, first non-empty wins. Default `HTTP_X_FORWARDED_FOR`, `HTTP_X_REAL_IP`, `HTTP_X_FORWARDED`, `HTTP_FORWARDED_FOR`, `HTTP_FORWARDED`
- `proxied_only` (`REAL_IP_PROXIED_ONLY`): only trust headers from trusted proxies. Default `True`

Non-routable IPs (private, loopback, link-local, multicast, reserved) are skipped; IPv4 is preferred over IPv6; IPv4-mapped IPv6 is unwrapped. `request.remote_addr` is `None` if no valid IP is found.

## License

Copyright 2025 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
