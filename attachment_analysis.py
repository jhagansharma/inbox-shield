import hashlib
import os
import requests
import fitz  # PyMuPDF for PDF
import docx
import pefile  # for PE (EXE) analysis
import json
from url_checker import load_api_keys




VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/files"
KNOWN_MALWARE_HASHES = {"d41d8cd98f00b204e9800998ecf8427e"}  # Add more hashes

API_KEYS = load_api_keys()
VIRUSTOTAL_API_KEY = API_KEYS.get("virustotal")
if not VIRUSTOTAL_API_KEY:
    raise ValueError("VirusTotal API key is missing. Please set it in the API keys file.")


def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()

def scan_with_virustotal(file_path):
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.post(VIRUSTOTAL_SCAN_URL, files=files, headers=headers)

        if response.status_code == 200:
            # Extract the analysis ID from the response
            analysis_id = response.json().get("data", {}).get("id")
            if not analysis_id:
                return {"status": "error", "details": "Failed to retrieve analysis ID from VirusTotal."}

            # Fetch detailed analysis results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)

            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                attributes = analysis_data.get("data", {}).get("attributes", {})
                stats = attributes.get("stats", {})
                scan_date = attributes.get("date", "N/A")
                harmless = stats.get("harmless", 0)
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)

                # Format the results
                return {
                    "status": "success",
                    "details": {
                        "scan_date": scan_date,
                        "harmless": harmless,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "undetected": undetected,
                        "analysis_url": f"https://www.virustotal.com/gui/file/{analysis_id}/detection"
                    }
                }
            else:
                return {"status": "error", "details": "Failed to fetch detailed analysis from VirusTotal."}
        else:
            return {"status": "error", "details": f"VirusTotal scan failed with status code {response.status_code}."}
    except Exception as e:
        return {"status": "error", "details": str(e)}

def analyze_pdf(file_path):
    try:
        doc = fitz.open(file_path)
        for page in doc:
            text = page.get_text()
            if "javascript" in text.lower():
                return True
    except Exception:
        pass
    return False

def analyze_docx(file_path):
    try:
        doc = docx.Document(file_path)
        for para in doc.paragraphs:
            if "AutoOpen" in para.text or "macro" in para.text.lower():
                return True
    except Exception:
        pass
    return False

def analyze_exe(file_path):
    try:
        pe = pefile.PE(file_path)
        suspicious_sections = ['.text', '.rdata', '.data', '.rsrc']
        for section in pe.sections:
            name = section.Name.decode().strip("\x00")
            if name not in suspicious_sections:
                return True
    except Exception:
        pass
    return False

def scan_attachment(file_path):
    result = {
        "file": file_path,
        "hash": get_file_hash(file_path),
        "suspicious": False,
        "reason": "",
        "virustotal": None
    }

    # Check against known malware hashes
    if result["hash"] in KNOWN_MALWARE_HASHES:
        result["suspicious"] = True
        result["reason"] = "Hash matched known malware signature."
        return result

    # File-specific analysis
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".pdf":
        if analyze_pdf(file_path):
            result["suspicious"] = True
            result["reason"] = "Suspicious JavaScript found in PDF."
    elif ext == ".docx":
        if analyze_docx(file_path):
            result["suspicious"] = True
            result["reason"] = "Possible macro or AutoOpen script in DOCX."
    elif ext == ".exe":
        if analyze_exe(file_path):
            result["suspicious"] = True
            result["reason"] = "Suspicious sections found in EXE file."

    # VirusTotal scan
    vt_result = scan_with_virustotal(file_path)
    result["virustotal"] = vt_result

    return result
