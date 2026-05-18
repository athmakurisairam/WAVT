# app.py
#
# WHAT THIS FILE DOES:
#   - Starts a web server using Flask
#   - Has 2 routes (URLs):
#       GET  /          -> serves the HTML page (index.html)
#       POST /api/scan  -> runs the scanner, returns JSON results
#
# HOW TO RUN:
#   python app.py
#   Then open: http://localhost:5000

from flask import Flask, request, jsonify, render_template
import re
from scanner import run_full_scan

app = Flask(__name__)


def is_valid_target(target):
    """
    Safety check - make sure target looks like a real domain or IP.
    Blocks localhost and private IPs.
    """
    if not target or len(target) > 100:
        return False, "Target is empty or too long"

    blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
    if target.lower() in blocked:
        return False, "Scanning localhost is not allowed"

    private = r"^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
    if re.match(private, target):
        return False, "Scanning private/internal IPs is not allowed"

    return True, ""


@app.route("/")
def index():
    """Serve the frontend HTML page."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Frontend sends: POST /api/scan { "target": "example.com" }
    We run the scan and return JSON results.
    """
    data   = request.get_json()
    target = data.get("target", "").strip()

    valid, reason = is_valid_target(target)
    if not valid:
        return jsonify({"error": reason}), 400

    results = run_full_scan(target)

    if results.get("error"):
        return jsonify({"error": results["error"]}), 400

    return jsonify(results)


if __name__ == "__main__":
    print("=" * 45)
    print("  WAVT - Web App Vulnerability Tester")
    print("  Running at http://localhost:5000")
    print("=" * 45)
    app.run(debug=True, port=5000)
