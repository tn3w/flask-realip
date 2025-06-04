# Flask-RealIP

A Flask extension that obtains the real IP address of clients behind proxies.

## Description

Flask-RealIP is a simple extension for Flask applications that automatically determines the real IP address of incoming requests, even when your application is behind one or more proxies. It properly handles:

- X-Forwarded-For and other proxy headers
- IPv4 and IPv6 addresses
- IPv4-mapped IPv6 addresses
- Address validation to prevent spoofing

## Installation

You can install Flask-RealIP using pip:

```bash
pip install flask-realip
```

Or from the source code:

```bash
git clone https://github.com/tn3w/flask-realip.git
cd flask-realip
pip install -e .
```

## Usage

### Basic Usage

```python
from flask import Flask, request
from flask_realip import RealIP

app = Flask(__name__)
real_ip = RealIP(app)

@app.route('/')
def index():
    return f"Your IP address is: {request.remote_addr}"
```

### Configuration

Flask-RealIP can be configured with the following options:

```python
# Initialize with custom options
real_ip = RealIP(
    app=app,
    trusted_proxies=['127.0.0.1', '10.0.0.0/8'],
    forwarded_headers=['HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR'],
    proxied_only=True
)
```

Or using Flask's configuration system:

```python
# Configure in Flask app
app = Flask(__name__)
app.config['REAL_IP_TRUSTED_PROXIES'] = ['127.0.0.1', '10.0.0.0/8']
app.config['REAL_IP_FORWARDED_HEADERS'] = ['HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR']
app.config['REAL_IP_PROXIED_ONLY'] = True

real_ip = RealIP(app)
```

### With Application Factory Pattern

```python
from flask import Flask
from flask_realip import RealIP

real_ip = RealIP()

def create_app():
    app = Flask(__name__)
    # Configure Flask app...
    
    real_ip.init_app(app)
    return app
```

## Configuration Options

- `trusted_proxies`: List of trusted proxy IP addresses that are allowed to set forwarding headers. Default: `['127.0.0.1', '::1']`
- `forwarded_headers`: List of headers to check for forwarded IPs, in order of preference. Default: `['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED']`
- `proxied_only`: If True, only apply the middleware for requests from trusted proxies. Default: `True`

## How It Works

When a request passes through proxies, the original client IP gets stored in headers like X-Forwarded-For. Flask-RealIP examines these headers from trusted proxies, validates the IP addresses, and makes them available through Flask's standard `request.remote_addr`.

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
