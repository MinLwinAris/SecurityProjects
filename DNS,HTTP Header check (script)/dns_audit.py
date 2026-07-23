#!/usr/bin/env python3
"""
dns_audit.py — Bulk DNS record checker.

Checks for each domain: A, CNAME, MX, NS, TXT, SPF, DMARC, DNSSEC.
Outputs a console summary and a CSV file.

Setup:
    pip install dnspython

Usage:
    # from a file (one domain per line):
    py dns_audit.py domains.txt

    # or pass domains directly:
    py dns_audit.py example.com example.org

    # custom resolver / output:
    py dns_audit.py domains.txt --resolver 1.1.1.1 --out results.csv
"""

import sys
import csv
import argparse

try:
    import dns.resolver
    import dns.flags
    import dns.name
except ImportError:
    sys.exit("Missing dependency. Run:  pip install dnspython")


def make_resolver(servers, timeout):
    r = dns.resolver.Resolver(configure=True)
    if servers:
        r.nameservers = servers
    r.timeout = timeout
    r.lifetime = timeout * 3
    return r


def query(resolver, name, rdtype):
    """Return (records_list, status, ad_flag)."""
    try:
        ans = resolver.resolve(name, rdtype, raise_on_no_answer=False)
        recs = [r.to_text() for r in ans] if ans.rrset is not None else []
        ad = bool(ans.response.flags & dns.flags.AD)
        if not recs:
            return [], ("AD_NO_DATA" if ad else "NO_RECORD"), ad
        return recs, "OK", ad
    except dns.resolver.NXDOMAIN:
        return [], "NODOMAIN", False
    except dns.resolver.NoNameservers:
        return [], "SERVFAIL", False
    except dns.exception.Timeout:
        return [], "TIMEOUT", False
    except Exception as e:
        return [], f"ERROR:{type(e).__name__}", False


def audit(resolver, domain):
    row = {"domain": domain}

    a_recs, a_status, _ = query(resolver, domain, "A")
    row["A"] = "; ".join(a_recs) or a_status

    cn_recs, cn_status, _ = query(resolver, domain, "CNAME")
    row["CNAME"] = "; ".join(cn_recs) or cn_status

    mx_recs, mx_status, _ = query(resolver, domain, "MX")
    row["MX"] = "; ".join(sorted(mx_recs)) or mx_status

    ns_recs, ns_status, _ = query(resolver, domain, "NS")
    row["NS"] = "; ".join(sorted(ns_recs)) or ns_status

    txt_recs, txt_status, _ = query(resolver, domain, "TXT")
    row["TXT"] = "; ".join(txt_recs) or txt_status

    # SPF lives inside TXT at the apex
    spf = [t for t in txt_recs if "v=spf1" in t.lower()]
    row["SPF"] = "; ".join(spf) if spf else "NONE"

    # DMARC lives at _dmarc.<domain> as a TXT record
    dmarc_recs, dmarc_status, _ = query(resolver, f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in dmarc_recs if "v=dmarc1" in t.lower()]
    row["DMARC"] = "; ".join(dmarc) if dmarc else (dmarc_status if not dmarc_recs else "NO_DMARC")

    # DNSSEC: signed zones publish DNSKEY and answers carry RRSIG; a validating
    # resolver also sets the AD (Authenticated Data) flag.
    dnskey_recs, dnskey_status, _ = query(resolver, domain, "DNSKEY")
    _, _, ad_flag = query(resolver, domain, "SOA")
    if dnskey_recs:
        row["DNSSEC"] = "SIGNED (AD)" if ad_flag else "FOUND"
    else:
        row["DNSSEC"] = "AD-set/no-DNSKEY-seen" if ad_flag else "NO_RECORD"

    return row


def main():
    ap = argparse.ArgumentParser(description="Bulk DNS record auditor")
    ap.add_argument("inputs", nargs="+", help="A domains file (one per line) and/or domains")
    ap.add_argument("--resolver", action="append", default=[],
                    help="DNS server IP (repeatable). Default: system resolver.")
    ap.add_argument("--timeout", type=float, default=6.0, help="Per-query timeout seconds")
    ap.add_argument("--out", default="dns_audit_results.csv", help="Output CSV path")
    args = ap.parse_args()

    # Collect domains: any input that's an existing file is read line-by-line,
    # everything else is treated as a literal domain.
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

    # de-dupe, preserve order
    seen, ordered = set(), []
    for d in domains:
        dl = d.lower().rstrip(".")
        if dl and dl not in seen:
            seen.add(dl)
            ordered.append(dl)
    domains = ordered

    if not domains:
        sys.exit("No domains found.")

    resolver = make_resolver(args.resolver, args.timeout)
    fields = ["domain", "DMARC", "SPF", "MX", "A", "CNAME", "TXT", "NS", "DNSSEC"]

    rows = []
    for i, d in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] {d}")
        row = audit(resolver, d)
        rows.append(row)
        # compact console line for quick scanning
        print(f"    DMARC={'Y' if row['DMARC'].lower().startswith('v=dmarc1') else 'N'} | "
              f"SPF={'Y' if row['SPF'] != 'NONE' else 'N'} | "
              f"MX={_short(row['MX'])} | "
              f"A={_short(row['A'])} | "
              f"DNSSEC={row['DNSSEC']}")

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"\nDone. {len(rows)} domains written to {args.out}")


def _short(s, n=40):
    s = s or ""
    return (s[:n] + "...") if len(s) > n else s


if __name__ == "__main__":
    main()
