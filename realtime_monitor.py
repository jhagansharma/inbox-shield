import time
import base64
import os
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google_auth import authenticate_user
from email_analyzer import analyze_email_headers
from attachment_analysis import scan_attachment
from email_security_checks import run_security_checks
from legitimacy_checker import calculate_legitimacy_score
import tempfile
import json

def get_gmail_service():
    creds = authenticate_user()
    service = build('gmail', 'v1', credentials=creds)
    return service

def download_email(service, msg_id):
    try:
        msg = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        raw_data = base64.urlsafe_b64decode(msg['raw'].encode('ASCII'))
        temp_path = os.path.join(tempfile.gettempdir(), f"{msg_id}.eml")
        with open(temp_path, 'wb') as f:
            f.write(raw_data)
        return temp_path
    except Exception as e:
        print(f"Failed to download email {msg_id}: {e}")
        return None

def monitor_inbox():
    print("🔄 Starting real-time Gmail monitoring...")
    service = get_gmail_service()
    last_checked_id = None

    while True:
        try:
            results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=5).execute()
            messages = results.get('messages', [])

            for message in messages:
                msg_id = message['id']
                if msg_id == last_checked_id:
                    continue

                email_path = download_email(service, msg_id)
                if not email_path:
                    continue

                print(f"📩 New Email: {msg_id}")
                email_data = analyze_email_headers(email_path)
                email_data['attachments'] = []  # You can add attachment extraction here

                # Analyze attachments
                attachment_results = []
                for file_path in email_data['attachments']:
                    result = scan_attachment(file_path)
                    attachment_results.append(result)

                # Security Checks
                sender = email_data.get('sender', '')
                security_results = run_security_checks(sender, eml_path=email_path)
                email_data['email_security'] = security_results

                # Scoring
                vt_api_key = os.getenv("VIRUSTOTAL_API_KEY") or "YOUR_FALLBACK_API_KEY"
                score, verdict = calculate_legitimacy_score(
                    email_details=security_results,
                    file_scan_results=attachment_results,
                    url_scan_results=email_data.get("urls", []),
                    api_key=vt_api_key
                )

                print(f"✅ Verdict: {verdict} (Score: {score})\n")
                print("="*60)

                last_checked_id = msg_id

        except HttpError as error:
            print(f"⚠️ An error occurred: {error}")
        time.sleep(30)  # Wait before polling again

if __name__ == "__main__":
    monitor_inbox()
