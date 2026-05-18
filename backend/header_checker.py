# scanner/header_checker.py
#
# WHAT THIS FILE DOES:
#   - Sends an HTTP request to the target website
#   - Reads the response headers (metadata the server sends back)
#   - Checks for missing security headers that protect users
#
# KEY CONCEPT — HTTP headers are like instructions the server gives to the browser.
#   "Strict-Transport-Security" tells the browser: always use HTTPS, never HTTP
#   "Content-Security-Policy" tells the browser: only load scripts from trusted sources
#   "X-Frame-Options" tells the browser: don't allow this page to be loaded in an iframe
#   Missing these = well-known vulnerabilities = OWASP findings

import requests

# Each header we check:
# KEY       = the actual header name
# title     = human readable name
# severity  = how bad it is if missing
# tip       = what to tell the developer to fix it
SECURITY_HEADERS = [
    {
        "key":      "Strict-Transport-Security",
        "title":    "Missing HSTS Header",
        "severity": "High",
        "tip":      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "owasp":    "A02 — Cryptographic Failures"
    },
    {
        "key":      "Content-Security-Policy",
        "title":    "Missing Content Security Policy",
        "severity": "Medium",
        "tip":      "Add a Content-Security-Policy header to prevent XSS attacks",
        "owasp":    "A03 — Injection (XSS)"
    },
    {
        "key":      "X-Frame-Options",
        "title":    "Missing X-Frame-Options",
        "severity": "Medium",
        "tip":      "Add: X-Frame-Options: DENY  (prevents clickjacking)",
        "owasp":    "A05 — Security Misconfiguration"
    },
    {
        "key":      "X-Content-Type-Options",
        "title":    "Missing X-Content-Type-Options",
        "severity": "Low",
        "tip":      "Add: X-Content-Type-Options: nosniff",
        "owasp":    "A05 — Security Misconfiguration"
    },
    {
        "key":      "Referrer-Policy",
        "title":    "Missing Referrer-Policy",
        "severity": "Low",
        "tip":      "Add: Referrer-Policy: no-referrer-when-downgrade",
        "owasp":    "A05 — Security Misconfiguration"
    }
]


def check_headers(target):
    """
    Fetch the target URL and inspect its response headers.
    Returns a list of missing security headers as findings.
    """
    # Make sure the URL has http:// or https://
    if not target.startswith("http"):
        url = "http://" + target
    else:
        url = target

    findings  = []
    headers_found = {}

    try:
        # Send GET request — verify=False means don't crash on bad SSL certs
        # timeout=5 means give up after 5 seconds
        response = requests.get(url, timeout=5, verify=False,
                                allow_redirects=True)
        headers_found = dict(response.headers)

        # Check each security header
        for h in SECURITY_HEADERS:
            if h["key"] not in headers_found:
                # Header is missing — this is a finding
                findings.append({
                    "port":        "HTTP",
                    "title":       h["title"],
                    "description": h["tip"],
                    "severity":    h["severity"],
                    "owasp":       h["owasp"],
                    "cve":         None
                })

        # Extra check: does the server reveal its version?
        # e.g. "Server: Apache/2.4.49" lets attackers look up CVEs for that version
        server = headers_found.get("Server", "")
        if server and any(char.isdigit() for char in server):
            findings.append({
                "port":        "HTTP",
                "title":       "Server Version Disclosed",
                "description": f"Server header reveals version: '{server}' — remove version info",
                "severity":    "Low",
                "owasp":       "A05 — Security Misconfiguration",
                "cve":         None
            })

    except requests.exceptions.ConnectionError:
        return {"error": f"Could not connect to {url}"}
    except requests.exceptions.Timeout:
        return {"error": f"Connection timed out: {url}"}
    except Exception as e:
        return {"error": str(e)}

    return {
        "headers_found": headers_found,
        "findings":      findings,
        "error":         None
    }
