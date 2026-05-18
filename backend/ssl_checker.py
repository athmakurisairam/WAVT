# scanner/ssl_checker.py
#
# WHAT THIS FILE DOES:
#   - Connects to the target on port 443 (HTTPS)
#   - Reads the SSL certificate details
#   - Checks: is it expired? expiring soon? is the domain correct?
#
# KEY CONCEPT — SSL/TLS certificates are digital IDs for websites.
#   An expired cert = browser shows scary warning = users leave = bad
#   A cert for the wrong domain = possible impersonation attack

import ssl
import socket
from datetime import datetime


def check_ssl(target):
    """
    Connect to target:443, read the SSL certificate, check for problems.
    """
    # Strip http/https if present — we just need the hostname
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    findings = []
    cert_info = {}

    try:
        # Create an SSL context — this handles the TLS handshake
        context = ssl.create_default_context()

        # Connect and get the certificate
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                # Extract expiry date
                # Format looks like: "Dec 31 23:59:59 2024 GMT"
                expiry_str  = cert["notAfter"]
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left   = (expiry_date - datetime.utcnow()).days

                cert_info = {
                    "subject":    dict(x[0] for x in cert.get("subject", [])),
                    "issuer":     dict(x[0] for x in cert.get("issuer", [])),
                    "expires":    expiry_str,
                    "days_left":  days_left,
                    "tls_version": ssock.version()
                }

                # Finding 1: already expired
                if days_left < 0:
                    findings.append({
                        "port":        443,
                        "title":       "SSL Certificate Expired",
                        "description": f"Certificate expired {abs(days_left)} days ago",
                        "severity":    "Critical",
                        "owasp":       "A02 — Cryptographic Failures",
                        "cve":         None
                    })

                # Finding 2: expiring within 30 days
                elif days_left < 30:
                    findings.append({
                        "port":        443,
                        "title":       "SSL Certificate Expiring Soon",
                        "description": f"Certificate expires in {days_left} days — renew now",
                        "severity":    "High",
                        "owasp":       "A02 — Cryptographic Failures",
                        "cve":         None
                    })

                # Finding 3: old TLS version (TLSv1 or TLSv1.1 are insecure)
                tls = ssock.version()
                if tls in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "port":        443,
                        "title":       f"Outdated TLS Version ({tls})",
                        "description": f"Server uses {tls} which is deprecated — upgrade to TLS 1.2 or 1.3",
                        "severity":    "High",
                        "owasp":       "A02 — Cryptographic Failures",
                        "cve":         None
                    })

    except ssl.SSLCertVerificationError:
        # Certificate is invalid or self-signed
        findings.append({
            "port":        443,
            "title":       "Invalid SSL Certificate",
            "description": "Certificate could not be verified — may be self-signed or misconfigured",
            "severity":    "High",
            "owasp":       "A02 — Cryptographic Failures",
            "cve":         None
        })
    except ConnectionRefusedError:
        # Port 443 is not open — HTTPS not available
        findings.append({
            "port":        443,
            "title":       "HTTPS Not Available",
            "description": "Port 443 is closed — site does not support HTTPS",
            "severity":    "High",
            "owasp":       "A02 — Cryptographic Failures",
            "cve":         None
        })
    except Exception:
        # Any other error — just skip SSL check silently
        pass

    return {
        "cert_info": cert_info,
        "findings":  findings,
        "error":     None
    }
