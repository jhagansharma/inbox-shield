import dns.resolver
import re
import requests
import json
from urllib.parse import urlparse
import dkim

# Load API keys from config.json
def load_api_keys():
    try:
        with open("config.json", "r") as f:
            return json.load(f)
    except Exception:
        return {}

API_KEYS = load_api_keys()

# === SPF CHECK ===
def check_spf(domain):
    try:
        answers = dns.resolver.resolve(f"{domain}", "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode()
                if decoded.startswith("v=spf1"):
                    return {"spf": "valid", "details": decoded}
        return {"spf": "invalid", "details": "No SPF record found"}
    except Exception as e:
        return {"spf": "error", "details": str(e)}

# === DKIM CHECK (simplified placeholder) ===
def check_dkim_signature(eml_path):
    try:
        with open(eml_path, "rb") as f:
            raw_email = f.read()

        if b"DKIM-Signature" not in raw_email:
            return {"dkim": "not_found", "details": "No DKIM-Signature header found."}

        is_valid = dkim.verify(raw_email)
        if is_valid:
            return {"dkim": "valid", "details": "DKIM signature verified successfully."}
        else:
            return {"dkim": "invalid", "details": "DKIM signature is present but invalid."}
    except Exception as e:
        return {"dkim": "error", "details": str(e)}

# === DMARC CHECK ===
def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            for txt_string in rdata.strings:
                decoded = txt_string.decode()
                if "v=DMARC1" in decoded:
                    return {"dmarc": "valid", "details": decoded}
        return {"dmarc": "invalid", "details": "No DMARC record found"}
    except Exception as e:
        return {"dmarc": "error", "details": str(e)}

# === WHOIS CHECK (API.Market) ===
def check_whois_magicapi(domain):
    api_key = API_KEYS.get("market_api_key")
    if not api_key:
        return {"whois": "error", "details": "API key not found in config"}

    url = "https://api.magicapi.dev/api/v1/whoisfreaks/whois-api/v1.0/whois"
    headers = {
        "accept": "application/json",
        "x-magicapi-key": api_key
    }
    params = {
        "whois": "live",
        "domainName": domain,
        "mode": "mini",
        "page": 1
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {"whois": "success", "details": data}
        else:
            return {"whois": "error", "details": f"HTTP {response.status_code}: {response.text}"}
    except Exception as e:
        return {"whois": "error", "details": str(e)}

# === FULL SECURITY CHECK ===
def run_security_checks(from_header,eml_path=None):
    try:
        # Extract domain from From: header
        match = re.search(r'@([A-Za-z0-9.-]+)', from_header)
        if not match:
            return {"error": "Invalid From header format"}
        domain = match.group(1)

        return {
            "domain": domain,
            "spf": check_spf(domain),
            "dkim": check_dkim_signature(eml_path) if eml_path else {"dkim": "skipped", "details": "No file provided"},
            "dmarc": check_dmarc(domain),
            "whois": check_whois_magicapi(domain)
        }
    except Exception as e:
        return {"error": str(e)}
