import requests
import time
import os
def get_virustotal_api_key():
    """
    Retrieves the VirusTotal API key from the environment variable.

    Returns:
        str: The VirusTotal API key.
    """
    api_key = os.getenv("49668fd76de995874d5bae3ed9306db5b571f26bb9f676f4e4c22a30c281ca53")
    if not api_key:
        print("Error: VirusTotal API key not found. Set the VIRUSTOTAL_API_KEY environment variable.")
        exit(1)
    return api_key

def scan_file_with_virustotal(api_key, file_path):

    upload_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    try:
        # Upload the file to VirusTotal
        with open(file_path, "rb") as file:
            print(f"Uploading file: {file_path} to VirusTotal...")
            response = requests.post(upload_url, headers=headers, files={"file": file})

        if response.status_code == 200:
            data = response.json()
            analysis_id = data["data"]["id"]
            print(f"File uploaded successfully. Analysis ID: {analysis_id}")

            # Poll for the scan results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            while True:
                print("Waiting for scan results...")
                result_response = requests.get(analysis_url, headers=headers)
                result_data = result_response.json()

                if result_data["data"]["attributes"]["status"] == "completed":
                    print("Scan completed.")
                    return result_data
                time.sleep(15)  # Wait for 15 seconds before polling again
        else:
            return {"error": f"Failed to upload file. HTTP {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": str(e)}
    
def calculate_legitimacy_score(email_details, file_scan_results, url_scan_results, api_key):

    score = 100  # Start with a perfect score

    # Deduct points for suspicious/malicious URLs
    for url_result in url_scan_results:
        if url_result["google_safe_browsing"]["status"] == "malicious":
            score -= 30
        if url_result["virustotal"]["status"] == "malicious":
            score -= 30
        if url_result["whois"]["status"] == "error":
            score -= 10  # Deduct points if WHOIS lookup fails
        if url_result.get("http_alert", False):  # Deduct points for http URLs
            score -= 5

    # Deduct points for suspicious/malicious attachments
    for file_result in file_scan_results:
        if file_result["status"] == "malicious":
            score -= 40
        elif file_result["status"] == "unknown":
            # Scan the file with VirusTotal
            scan_result = scan_file_with_virustotal(api_key, file_result["file_path"])
            if "error" in scan_result:
                print(f"Error scanning file: {scan_result['error']}")
                score -= 20  # Deduct points if the file could not be scanned
            else:
                # Analyze VirusTotal scan results
                malicious_count = scan_result["data"]["attributes"]["stats"]["malicious"]
                if malicious_count > 0:
                    score -= 40  # Deduct points for malicious files

    # Deduct points for missing SPF/DKIM/DMARC checks
    if email_details.get("spf", {}).get("status") != "valid":
        score -= 10
    if email_details.get("dkim", {}).get("status") != "valid":
        score -= 10
    if email_details.get("dmarc", {}).get("status") != "valid":
        score -= 10

    # Ensure the score does not go below 0
    score = max(score, 0)

    # Determine the verdict
    if score >= 80:
        verdict = "Legitimate"
    elif score >= 50:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"

    return score, verdict