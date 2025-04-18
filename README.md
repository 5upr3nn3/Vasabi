# Deliberately Vulnerable Flask Web App for DAST Benchmarking

**WARNING: This application is intentionally insecure and must only be run in a safe, isolated environment for testing and research. DO NOT deploy or expose to public networks.**

## Purpose

This app is designed for benchmarking and evaluating DAST. It includes:
- **Real, intentionally introduced vulnerabilities** (e.g., SQL Injection, XSS, Command Injection, etc.)
- **Carefully crafted false positives** (endpoints that appear vulnerable to scanners but are implemented securely)

## Features
- Per-request and per-response logging for benchmarking and scanner correlation (see `benchmark.log`)
- Standardized response header (`X-Benchmark-Endpoint`) for endpoint correlation
- `/log-scanner-result` endpoint for scanner result integration (writes to `scanner_results.log`)

## How to Run

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the app:**
   ```bash
   python app.py
   ```
3. **Browse endpoints:**
   Visit [http://localhost:5000/](http://localhost:5000/) and try the various routes.


## Files
- `app.py` — Main Flask app with all endpoints
- `vulnerabilities_list.txt` — List of all real vulnerabilities and false positives
- `benchmark.log` — Per-request/response benchmark log (auto-generated)
- `scanner_results.log` — DAST scanner output log (via `/log-scanner-result`)
- `requirements.txt` — Python dependencies
- `templates/` — HTML templates for endpoints
- `static/` — Static files (e.g., JS template false positive)

## Safety Notice
- This app is for **testing and research only**.
- Do **not** use any real data, credentials, or expose this app to untrusted networks.
- Review and clean up your environment after use.

## Contact
For questions or contributions, please open an issue or pull request in your research environment.
