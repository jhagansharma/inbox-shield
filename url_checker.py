import requests
import base64
import whois
import json 
import os


def load_api_keys():
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
        return {
            "google": config.get("google_api_key"),
            "virustotal": config.get("virustotal_api_key"),
            "market": config.get("market_api_key")
        }
    except Exception:
        return {"google": "", "virustotal": "", "market": ""}

API_KEYS = load_api_keys()

def check_google_safe_browsing(api_key, url):
    
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "email-analysis-tool",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(endpoint, params={"key": api_key}, json=payload)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                return {"url": url, "status": "malicious", "details": data["matches"]}
            else:
                return {"url": url, "status": "safe", "details": "No threats found"}
        else:
            return {"url": url, "status": "error", "details": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "error", "details": str(e)}



def check_whois_magicapi(domain, api_key="YOUR_API_MARKET_KEY"):
    url = "https://api.magicapi.dev/api/v1/whoisfreaks/whois-api/v1.0/whois"
    headers = {
        "accept": "application/json",
        "x-magicapi-key": api_key
    }
    params = {
        "whois": "live",
        "domainName": domain,
        "mode": "mini",     # 'mini' or 'full'
        "page": 1
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {"status": "success", "details": data}
        else:
            return {"status": "error", "details": f"HTTP {response.status_code}: {response.text}"}
    except Exception as e:
        return {"status": "error", "details": str(e)}


def check_virustotal(api_key, url):
   
    endpoint = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": api_key}
    try:
        # Encode the URL in base64 format as required by VirusTotal
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"{endpoint}/{url_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious_count > 0:
                return {"url": url, "status": "malicious", "details": data}
            else:
                return {"url": url, "status": "safe", "details": "No threats found"}
        else:
            return {"url": url, "status": "error", "details": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "error", "details": str(e)}

def check_whois(domain):
 
    try:
        domain_info = whois.whois(domain)
        return {
            "status": "success",
            "details": {
                "domain_name": domain_info.domain_name,
                "creation_date": domain_info.creation_date,
                "expiration_date": domain_info.expiration_date,
                "registrar": domain_info.registrar,
                "name_servers": domain_info.name_servers
            }
        }
    except Exception as e:
        return {"status": "error", "details": str(e)}


def check_url(url):

    google_api_key = API_KEYS["google"]
    virustotal_api_key = API_KEYS["virustotal"]
    market_api_key = API_KEYS["market"]
    # Initialize the result dictionary
    result = {
        "url": url,
        "google_safe_browsing": {"status": "error", "details": "Not checked"},
        "virustotal": {"status": "error", "details": "Not checked"},
        "whois": {"status": "error", "details": "Not checked"}
    }

    # Check the URL using Google Safe Browsing API
    try:
        google_result = check_google_safe_browsing(google_api_key, url)
        result["google_safe_browsing"] = google_result
    except Exception as e:
        result["google_safe_browsing"] = {"status": "error", "details": str(e)}

    # Check the URL using VirusTotal API
    try:
        virustotal_result = check_virustotal(virustotal_api_key, url)
        result["virustotal"] = virustotal_result
    except Exception as e:
        result["virustotal"] = {"status": "error", "details": str(e)}

    # Perform WHOIS lookup
    try:
        domain = url.split("//")[-1].split("/")[0]
        whois_result = check_whois_magicapi(domain, api_key=market_api_key)
        result["whois"] = whois_result
    except Exception as e:
        result["whois"] = {"status": "error", "details": str(e)}

    return result


def scan_url_virustotal(api_key, url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key}

        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            total_engines = sum(stats.values())
            return {
                "status": "success",
                "details": stats,
                "total_engines": total_engines
            }
        elif response.status_code == 404:
            return {"status": "error", "details": "URL not found in VirusTotal"}
        else:
            return {"status": "error", "details": f"HTTP {response.status_code}: {response.text}"}
    except Exception as e:
        return {"status": "error", "details": str(e)}
