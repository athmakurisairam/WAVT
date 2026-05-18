# scanner/__init__.py
#
# WHAT THIS FILE DOES:
#   - Makes the scanner/ folder a Python package
#   - Provides one single function: run_full_scan()
#   - Flask calls this one function and gets everything back
#
# Think of this as the "coordinator" — it calls all 4 modules
# and combines their results into one clean dictionary.

from .port_scanner  import run_port_scan
from .header_checker import check_headers
from .ssl_checker   import check_ssl
from .cve_lookup    import enrich_with_cves


def run_full_scan(target):
    """
    Run all WAVT scanner modules against a target.
    Returns one combined result dictionary.

    Called by Flask like:
        results = run_full_scan("example.com")
    """
    # Clean up target — remove http/https for port scanning
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]

    print(f"[WAVT] Starting scan: {clean_target}")

    # ── Module 1: Port Scanner ──────────────────────
    print("[WAVT] Running port scan...")
    port_results = run_port_scan(clean_target)

    if port_results.get("error"):
        # If we can't even resolve the hostname, stop here
        return {"error": port_results["error"]}

    # ── Module 2: HTTP Header Checker ───────────────
    print("[WAVT] Checking HTTP headers...")
    header_results = check_headers(clean_target)

    # ── Module 3: SSL Certificate Checker ───────────
    print("[WAVT] Checking SSL certificate...")
    ssl_results = check_ssl(clean_target)

    # ── Module 4: CVE Lookup ─────────────────────────
    print("[WAVT] Looking up CVEs...")
    cve_findings = enrich_with_cves(port_results.get("open_ports", []))

    # ── Combine all findings ─────────────────────────
    all_findings = []

    # Port-based risk flags (exposed databases, SMB, etc.)
    for flag in port_results.get("risk_flags", []):
        all_findings.append({
            "port":        flag["port"],
            "title":       flag["title"],
            "description": flag["description"],
            "severity":    flag["severity"],
            "owasp":       "A05 — Security Misconfiguration",
            "cve":         None
        })

    # Header findings
    for f in header_results.get("findings", []):
        all_findings.append(f)

    # SSL findings
    for f in ssl_results.get("findings", []):
        all_findings.append(f)

    # CVE findings
    for f in cve_findings:
        all_findings.append(f)

    # Sort findings: Critical first, then High, Medium, Low
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    # Count by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        key = f["severity"].lower()
        if key in counts:
            counts[key] += 1

    print(f"[WAVT] Scan complete. {len(all_findings)} findings.")

    return {
        "target":     clean_target,
        "ip":         port_results.get("ip"),
        "open_ports": port_results.get("open_ports", []),
        "findings":   all_findings,
        "counts":     counts,
        "cert_info":  ssl_results.get("cert_info", {}),
        "error":      None
    }
