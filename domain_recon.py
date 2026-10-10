#!/usr/bin/env python3
"""
domain_recon.py - quick passive recon for a domain you own or are allowed to assess.

Checks: DNS records, SPF/DMARC, HTTPS security headers, TLS certificate expiry,
and subdomains seen in public certificate transparency logs (crt.sh).
Everything here is passive / public data. No port scanning, no brute forcing.

Usage:
    python domain_recon.py example.com
    python domain_recon.py example.com --json > report.json
    python domain_recon.py example.com --no-subdomains

Install:
    pip install requests dnspython
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone

import dns.resolver
import requests

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA"]


def dns_records(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    out = {}
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            out[rtype] = sorted(r.to_text() for r in answers)
        except Exception:
            out[rtype] = []
    return out


def txt_lookup(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []


def email_security(domain, txt_records):
    spf = [t.strip('"') for t in txt_records if "v=spf1" in t]
    dmarc = [t for t in txt_lookup(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    notes = []
    if not spf:
        notes.append("No SPF record found.")
    elif any("+all" in s for s in spf):
        notes.append("SPF uses +all, which allows anyone to send as this domain.")
    if not dmarc:
        notes.append("No DMARC record found.")
    elif "p=none" in dmarc[0].replace(" ", "").lower():
        notes.append("DMARC policy is p=none (monitoring only, not enforcing).")
    return {"spf": spf, "dmarc": dmarc, "notes": notes}


def http_headers(domain):
    try:
        r = requests.get(f"https://{domain}", timeout=8, allow_redirects=True,
                         headers={"User-Agent": "domain-recon/1.0"})
    except requests.RequestException as e:
        return {"error": str(e)}
    headers = {k.lower(): v for k, v in r.headers.items()}
    return {
        "final_url": r.url,
        "status": r.status_code,
        "server": headers.get("server"),
        "present": {h: headers[h] for h in SECURITY_HEADERS if h in headers},
        "missing": [h for h in SECURITY_HEADERS if h not in headers],
    }


def tls_info(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert["issuer"])
        return {
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "expires": expires.isoformat(),
            "days_left": (expires - datetime.now(timezone.utc)).days,
        }
    except Exception as e:
        return {"error": str(e)}


def subdomains(domain):
    try:
        r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=20)
        r.raise_for_status()
        found = set()
        for entry in r.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain):
                    found.add(name)
        return sorted(found)
    except Exception as e:
        return [f"lookup failed: {e}"]


def run(domain, include_subs=True):
    records = dns_records(domain)
    report = {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "dns": records,
        "email_security": email_security(domain, records["TXT"]),
        "http": http_headers(domain),
        "tls": tls_info(domain),
    }
    if include_subs:
        report["subdomains"] = subdomains(domain)
    return report


def print_report(r):
    def h(title):
        print(f"\n== {title} " + "=" * (60 - len(title)))

    print(f"Recon report for {r['domain']}  ({r['scanned_at']})")

    h("DNS")
    for rtype, vals in r["dns"].items():
        if vals:
            print(f"{rtype:5} " + ("\n      ".join(vals)))

    h("Email security")
    es = r["email_security"]
    print("SPF:  ", es["spf"] or "none")
    print("DMARC:", es["dmarc"] or "none")
    for n in es["notes"]:
        print(" !", n)

    h("HTTPS")
    http = r["http"]
    if "error" in http:
        print("error:", http["error"])
    else:
        print(f"{http['status']} {http['final_url']}  (server: {http['server']})")
        print("present:", ", ".join(http["present"]) or "none")
        print("missing:", ", ".join(http["missing"]) or "none")

    h("TLS certificate")
    tls = r["tls"]
    if "error" in tls:
        print("error:", tls["error"])
    else:
        print(f"issuer: {tls['issuer']}  expires: {tls['expires']}  ({tls['days_left']} days left)")

    if "subdomains" in r:
        h(f"Subdomains from CT logs ({len(r['subdomains'])})")
        for s in r["subdomains"]:
            print(" ", s)


def main():
    p = argparse.ArgumentParser(description="Passive domain recon.")
    p.add_argument("domain")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--no-subdomains", action="store_true", help="skip the crt.sh lookup")
    args = p.parse_args()

    domain = args.domain.lower().strip().removeprefix("https://").removeprefix("http://").strip("/")
    report = run(domain, include_subs=not args.no_subdomains)
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print_report(report)


if __name__ == "__main__":
    main()
