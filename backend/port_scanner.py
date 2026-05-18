# scanner/port_scanner.py
#
# WHAT THIS FILE DOES:
#   - Connects to a target host on multiple ports (like knocking on doors)
#   - If a port is open, it tries to read the "banner" (service name + version)
#   - Uses threads so all ports are checked at the same time (fast)
#
# KEY CONCEPT — A port is like a door on a building (the server).
#   Port 80  = HTTP  (website)
#   Port 443 = HTTPS (secure website)
#   Port 22  = SSH   (remote login)
#   Port 3306= MySQL (database)
#   An open database port on the public internet = BAD

import socket
import concurrent.futures

# The ports we check — these are the most commonly attacked ports
PORTS_TO_SCAN = [
    21, 22, 23, 25, 53, 80, 110, 143,
    443, 445, 3000, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 27017
]

# Known service names for common ports
SERVICE_NAMES = {
    21: "FTP",    22: "SSH",     23: "Telnet",
    25: "SMTP",   53: "DNS",     80: "HTTP",
    110: "POP3",  143: "IMAP",   443: "HTTPS",
    445: "SMB",   3000: "Dev Server", 3306: "MySQL",
    3389: "RDP",  5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis",8080: "HTTP-Alt",   8443: "HTTPS-Alt",
    8888: "Jupyter/Dev",              27017: "MongoDB"
}

# Ports that should NEVER be open on the public internet
RISKY_PORTS = {
    21:    ("FTP open — sends passwords in plain text",            "Medium"),
    23:    ("Telnet open — completely unencrypted",                "High"),
    445:   ("SMB exposed — used by ransomware like WannaCry",      "High"),
    3306:  ("MySQL database exposed to internet",                  "High"),
    3389:  ("RDP exposed — frequently brute-forced",               "High"),
    5432:  ("PostgreSQL database exposed to internet",             "High"),
    5900:  ("VNC remote desktop exposed",                          "High"),
    6379:  ("Redis exposed — no auth by default",                  "Critical"),
    27017: ("MongoDB exposed — no auth by default",                "Critical"),
}


def grab_banner(ip, port):
    """
    Try to read what service is running on this port.
    Example: port 22 might say "SSH-2.0-OpenSSH_8.9"
    This tells us the exact software and version — useful for CVE lookup.
    """
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))

        # For web ports, send a simple HTTP request to get a response
        if port in (80, 8080, 8000, 8888, 3000):
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        banner = s.recv(512).decode("utf-8", errors="ignore").strip()
        s.close()
        # Return only the first line, max 100 chars
        return banner.split("\n")[0][:100]
    except Exception:
        return ""


def check_single_port(ip, port):
    """
    Try to connect to one port. Returns result dict if open, None if closed.
    connect_ex() returns 0 if connection succeeded (port is open).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))  # 0 = open, anything else = closed
        s.close()

        if result == 0:
            return {
                "port":    port,
                "service": SERVICE_NAMES.get(port, "Unknown"),
                "banner":  grab_banner(ip, port)
            }
    except Exception:
        pass
    return None


def run_port_scan(target):
    """
    Main function — scans all ports and returns findings.
    Uses ThreadPoolExecutor to scan all ports at the same time.
    Without threads: 20 ports × 1 second timeout = 20 seconds
    With threads:    all 20 ports checked simultaneously = ~1-2 seconds
    """
    # Step 1 — turn domain name into IP address
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"error": f"Could not resolve hostname: {target}"}

    open_ports = []

    # Step 2 — scan all ports concurrently (at the same time)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_single_port, ip, p) for p in PORTS_TO_SCAN]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:  # not None means port is open
                open_ports.append(result)

    # Sort by port number so output looks clean
    open_ports.sort(key=lambda x: x["port"])

    # Step 3 — flag risky open ports
    risk_flags = []
    open_port_numbers = {p["port"] for p in open_ports}

    for port, (description, severity) in RISKY_PORTS.items():
        if port in open_port_numbers:
            risk_flags.append({
                "port":        port,
                "title":       f"{SERVICE_NAMES.get(port, 'Service')} Exposed",
                "description": description,
                "severity":    severity
            })

    # Check: HTTP open but no HTTPS
    if 80 in open_port_numbers and 443 not in open_port_numbers:
        risk_flags.append({
            "port":        80,
            "title":       "No HTTPS",
            "description": "Site runs on HTTP only — traffic is unencrypted",
            "severity":    "Medium"
        })

    return {
        "ip":         ip,
        "open_ports": open_ports,
        "risk_flags": risk_flags,
        "error":      None
    }
