#!/usr/bin/env python3
"""
header_audit.py — Bulk HTTP security-header checker.

For each domain it fetches the site over HTTPS (falling back to HTTP) and
evaluates these response headers. Verdicts:

    Strong                    = configured strictly to standard, OR
                                (for Server / X-Powered-By) hidden/absent.
    Weak                      = present but below standard, OR
                                (for Server / X-Powered-By) exposed/shown.
    Missing: Should Configure = a protective header that should exist is absent.
    NoWS: No WebService       = the site did not respond, so nothing could be
                                tested (expected for parked/reserved domains).

Headers checked:
    Referrer-Policy
    Server                     (info-leak header: best when absent/generic)
    X-Content-Type-Options
    X-Frame-Options
    X-Powered-By               (info-leak header: best when absent)
    Strict-Transport-Security
    Content-Security-Policy

Outputs a console summary and a CSV file.

Setup:
    pip install requests

Usage:
    py header_audit.py domains.txt
    py header_audit.py example.com example.org
    py header_audit.py domains.txt --timeout 10 --out headers.csv
"""

import sys
import csv
import argparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("Missing dependency. Run:  pip install requests")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

MISSING = "Missing: Should Configure"
NOWS = "NoWS: No WebService"

# Protective headers count toward the score; info-leak headers are graded
# separately (their ideal state is "absent").
PROTECTIVE = ["Referrer-Policy", "X-Content-Type-Options", "X-Frame-Options",
              "Strict-Transport-Security", "Content-Security-Policy"]

HEADER_COLS = ("Referrer-Policy", "Server", "X-Content-Type-Options",
               "X-Frame-Options", "X-Powered-By",
               "Strict-Transport-Security", "Content-Security-Policy")


def tag(verdict, value=""):
    """Compose a cell like 'Strong: nosniff' or 'Weak: ...'."""
    return f"{verdict}: {value}" if value else verdict


def eval_referrer_policy(v):
    if v is None:
        return MISSING, False
    safe = {"no-referrer", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin"}
    tokens = {t.strip().lower() for t in v.split(",")}
    if tokens & safe:
        return tag("Strong", v), True
    return tag("Weak", v), False


def eval_xcto(v):
    if v is None:
        return MISSING, False
    if v.strip().lower() == "nosniff":
        return tag("Strong", v), True
    return tag("Weak", v), False


def eval_xfo(v):
    if v is None:
        return MISSING, False
    val = v.strip().lower()
    if val in ("deny", "sameorigin"):
        return tag("Strong", v), True
    return tag("Weak", v), False


def eval_hsts(v):
    if v is None:
        return MISSING, False
    lower = v.lower()
    max_age = None
    for part in lower.split(";"):
        part = part.strip()
        if part.startswith("max-age"):
            try:
                max_age = int(part.split("=", 1)[1].strip())
            except (IndexError, ValueError):
                max_age = None
    extras = []
    if "includesubdomains" in lower:
        extras.append("+subdomains")
    if "preload" in lower:
        extras.append("+preload")
    suffix = (" " + " ".join(extras)) if extras else ""
    if max_age is None:
        return tag("Weak", "no max-age"), False
    if max_age >= 31536000:            # >= 1 year
        return tag("Strong", f"max-age={max_age}{suffix}"), True
    return tag("Weak", f"max-age={max_age} (<1yr){suffix}"), False


def eval_csp(v):
    if v is None:
        return MISSING, False
    low = v.lower()
    weak_bits = []
    if "unsafe-inline" in low:
        weak_bits.append("unsafe-inline")
    if "unsafe-eval" in low:
        weak_bits.append("unsafe-eval")
    if "default-src *" in low or "default-src 'unsafe" in low:
        weak_bits.append("wide default-src")
    if weak_bits:
        return tag("Weak", "present but " + ", ".join(weak_bits)), False
    return tag("Strong", "present"), True


def eval_infoleak(name, v):
    """Server / X-Powered-By: hidden/absent is Strong, exposed is Weak."""
    if v is None:
        return "Strong: hidden", True
    return tag("Weak", v), False


def fetch(url, timeout, verify=True):
    return requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                        allow_redirects=True, verify=verify)


def audit(domain, timeout):
    row = {"domain": domain}
    host = domain.replace("https://", "").replace("http://", "").strip("/")
    resp = None
    scheme_used = ""
    error = ""

    # Try HTTPS first, then plain HTTP as a fallback (a finding in itself).
    for scheme in ("https", "http"):
        try:
            resp = fetch(f"{scheme}://{host}", timeout)
            scheme_used = scheme
            break
        except requests.exceptions.SSLError as e:
            # retry HTTPS without cert verification so we still see headers
            try:
                resp = fetch(f"https://{host}", timeout, verify=False)
                scheme_used = "https (cert INVALID)"
                break
            except Exception:
                error = f"SSLError:{type(e).__name__}"
        except requests.exceptions.RequestException as e:
            error = f"{type(e).__name__}"

    if resp is None:
        row["HTTPS"] = "FAIL"
        row["Status"] = error or "no response"
        for h in HEADER_COLS:
            row[h] = NOWS
        row["Score"] = "NoWS"
        return row

    h = resp.headers  # case-insensitive dict
    row["HTTPS"] = scheme_used
    row["Status"] = str(resp.status_code)

    rp, rp_ok = eval_referrer_policy(h.get("Referrer-Policy"))
    sv, sv_ok = eval_infoleak("Server", h.get("Server"))
    xc, xc_ok = eval_xcto(h.get("X-Content-Type-Options"))
    xf, xf_ok = eval_xfo(h.get("X-Frame-Options"))
    xp, xp_ok = eval_infoleak("X-Powered-By", h.get("X-Powered-By"))
    hs, hs_ok = eval_hsts(h.get("Strict-Transport-Security"))
    cs, cs_ok = eval_csp(h.get("Content-Security-Policy"))

    row["Referrer-Policy"] = rp
    row["Server"] = sv
    row["X-Content-Type-Options"] = xc
    row["X-Frame-Options"] = xf
    row["X-Powered-By"] = xp
    row["Strict-Transport-Security"] = hs
    row["Content-Security-Policy"] = cs

    score = sum([rp_ok, xc_ok, xf_ok, hs_ok, cs_ok])
    row["Score"] = f"{score}/{len(PROTECTIVE)}"
    return row


def _short(s, n=34):
    s = s or ""
    return (s[:n] + "...") if len(s) > n else s


def main():
    ap = argparse.ArgumentParser(description="Bulk HTTP security-header auditor")
    ap.add_argument("inputs", nargs="+", help="A domains file (one per line) and/or domains")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds")
    ap.add_argument("--out", default="header_audit_results.csv", help="Output CSV path")
    args = ap.parse_args()

    import os
    domains = []
    for item in args.inputs:
        if os.path.isfile(item):
            with open(item, encoding="utf-8-sig", errors="ignore") as f:
                for line in f:
                    d = line.strip().split()[0] if line.strip() else ""
                    if d and not d.startswith("#"):
                        domains.append(d)
        else:
            domains.append(item.strip())

    seen, ordered = set(), []
    for d in domains:
        dl = d.lower().rstrip(".")
        if dl and dl not in seen:
            seen.add(dl)
            ordered.append(dl)
    domains = ordered

    if not domains:
        sys.exit("No domains found.")

    fields = ["domain", "HTTPS", "Status", "Referrer-Policy", "Server",
              "X-Content-Type-Options", "X-Frame-Options", "X-Powered-By",
              "Strict-Transport-Security", "Content-Security-Policy", "Score"]

    rows = []
    for i, d in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] {d}")
        row = audit(d, args.timeout)
        rows.append(row)
        print(f"    {row['HTTPS']} {row['Status']} | Score {row['Score']} | "
              f"HSTS={_short(row['Strict-Transport-Security'])} | "
              f"CSP={_short(row['Content-Security-Policy'])}")

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"\nDone. {len(rows)} domains written to {args.out}")


if __name__ == "__main__":
    main()
