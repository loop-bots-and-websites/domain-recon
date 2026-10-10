# domain-recon

Passive recon for a domain you own or are allowed to assess. Uses public data only: no port scanning, no brute forcing.

## What it checks

- DNS records (A, AAAA, MX, NS, TXT, CAA)
- SPF and DMARC, with notes on weak setups
- HTTPS security headers (present vs missing)
- TLS certificate issuer and days until expiry
- Subdomains seen in certificate transparency logs (crt.sh)

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python domain_recon.py example.com
python domain_recon.py example.com --json > report.json
python domain_recon.py example.com --no-subdomains
```

## Disclaimer

Only run this against domains you own or have permission to assess.

Built by [NANTHEDU](https://nanthedu.dpdns.org).
