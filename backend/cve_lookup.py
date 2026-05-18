# scanner/cve_lookup.py
#
# WHAT THIS FILE DOES:
#   - Takes a service name + version (e.g. "Apache 2.4.49")
#   - Queries the NVD (National Vulnerability Database) free API
#   - Returns real CVEs (known vulnerabilities) for that software
#
# KEY CONCEPT — CVE = Common Vulnerabilities and Exposures
#   Every discovered vulnerability gets a CVE ID like "CVE-2021-41773"
#   CVSS Score = how dangerous it is (0-10, higher = worse)
#   The NVD is run by the US government and is free to query

import requests


def lookup_cves(service_name, version=None):
    """
    Search NVD API for CVEs matching the service.
    Returns up to 3 most relevant CVEs.

    Example:
        lookup_cves("Apache", "2.4.49")
        → [{"id": "CVE-2021-41773", "score": 9.8, "summary": "Path traversal..."}]
    """
    # Build the search keyword
    keyword = service_name
    if version:
        keyword = f"{service_name} {version}"

    try:
        # NVD API v2 endpoint — free, no API key needed for basic use
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 3  # only get top 3 results
        }

        response = requests.get(url, params=params, timeout=8)

        if response.status_code != 200:
            return []

        data = response.json()
        cves = []

        # Parse the response
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Get the English description
            descriptions = cve.get("descriptions", [])
            summary = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    summary = d.get("value", "")[:150]  # first 150 chars
                    break

            # Get CVSS score (how dangerous: 0-10)
            score = None
            metrics = cve.get("metrics", {})

            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if version_key in metrics:
                    score_data = metrics[version_key][0].get("cvssData", {})
                    score = score_data.get("baseScore")
                    break

            if cve_id and summary:
                cves.append({
                    "id":      cve_id,
                    "score":   score,
                    "summary": summary
                })

        return cves

    except Exception:
        # If NVD API is down or slow, just return empty — don't crash the scan
        return []


def enrich_with_cves(open_ports):
    """
    Takes the list of open ports from port_scanner.py
    and adds CVE data to any port where we know the service + version.

    Returns list of CVE findings (only for ports with known vulnerabilities).
    """
    cve_findings = []

    for port_info in open_ports:
        service = port_info.get("service", "")
        banner  = port_info.get("banner", "")

        # Skip if we don't know what's running
        if service == "Unknown" or not service:
            continue

        # Extract version from banner if possible
        # e.g. "Apache/2.4.49" → service="Apache", version="2.4.49"
        version = None
        if "/" in banner:
            parts   = banner.split("/")
            version = parts[1].split(" ")[0] if len(parts) > 1 else None

        # Query NVD
        cves = lookup_cves(service, version)

        for cve in cves:
            # Only flag if CVSS score is 7.0+ (High or Critical)
            if cve["score"] and float(cve["score"]) >= 7.0:
                severity = "Critical" if float(cve["score"]) >= 9.0 else "High"
                cve_findings.append({
                    "port":        port_info["port"],
                    "title":       f"CVE found in {service}",
                    "description": cve["summary"],
                    "severity":    severity,
                    "owasp":       "A06 — Vulnerable Components",
                    "cve":         cve["id"],
                    "cvss":        cve["score"]
                })

    return cve_findings
