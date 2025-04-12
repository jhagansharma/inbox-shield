import os
import json
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_gmail_service():
    try:
        creds = None
        token_path = os.path.join(os.path.dirname(__file__), "token.json")
        credentials_path = os.path.join(os.path.dirname(__file__), "credentials.json")
        print(f"Looking for token.json at: {token_path}")
        
        if os.path.exists(token_path):
            print(f"token.json found at: {token_path}")
            try:
                creds = Credentials.from_authorized_user_file(token_path, SCOPES)
            except Exception as e:
                print(f"Error reading token.json: {e}")
                print("Deleting corrupted token.json file. Please re-authenticate.")
                os.remove(token_path)
                return None
        else:
            print("token.json not found. Please authenticate.")
            if not os.path.exists(credentials_path):
                print("credentials.json not found. Please add your Google API credentials.")
                return None
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(token_path, 'w') as token:
                token.write(creds.to_json())
            
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception as e:
                    print(f"Error refreshing token: {e}")
                    return None
            else:
                print("Authentication required. Run Google OAuth process.")
                return None
                
        try:
            service = build("gmail", "v1", credentials=creds)
            # Test the service with a simple API call
            service.users().getProfile(userId="me").execute()
            return service
        except Exception as e:
            print(f"Error building Gmail service: {e}")
            return None
            
    except Exception as e:
        print(f"Unexpected error in get_gmail_service: {e}")
        return None