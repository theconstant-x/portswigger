"""
proxies.py — route all requests through Burp Suite for inspection/tampering.

Make sure Burp's proxy listener is running on 127.0.0.1:8080 (default)
and "Intercept" is off unless you want to manually step through requests.
"""

import urllib3

# PortSwigger lab certs aren't trusted by default — suppress the noisy warning
# since we're intentionally disabling verification (lab traffic only).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BURP_PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# Pass this into every requests call: requests.get(url, proxies=BURP_PROXIES, verify=False)
VERIFY_SSL = False
