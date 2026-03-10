import imaplib
import email
from email.header import decode_header
import time
import sys
import os
import re
import requests
from urllib.parse import urlparse
import winsound

# Add project root to path to import scanner modules
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Fix Nmap Path on Windows (if not in system PATH)
if sys.platform.startswith("win"):
    nmap_paths = [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
    for path in nmap_paths:
        if os.path.exists(path):
            os.environ['PATH'] += ";" + path

from scanner.nmap_scan import scan_target
from parser.scan_parser import analyze_risk
try:
    from nmap import PortScannerError
except ImportError:
    class PortScannerError(Exception): pass

# ==========================================
# 🔧 CONFIGURATION
# ==========================================
EMAIL_USER = "aniketu0807@gmail.com"   # <--- The email address receiving the messages
EMAIL_PASS = "tdtk ikhv zkig ktxu"      # <--- The App Password for the receiving account
SERVER_URL = "http://localhost:5001/trigger_alert"

TRUSTED_SENDERS = [
    "notifications@github.com",
    "no-reply@accounts.google.com",
    # Add other trusted email addresses or domains here
]
# ==========================================

def clean_text(text):
    """Removes HTML tags and extra whitespace."""
    text = re.sub('<[^<]+?>', '', text)
    return " ".join(text.split())

class GmailClient:
    """A client to handle IMAP connections and email processing for Gmail."""
    def __init__(self, user, password):
        self.user = user
        self.password = password
        self.mail = None

    def connect(self):
        """Connects and logs into the Gmail IMAP server."""
        try:
            print("   [Conn] Connecting to Gmail...")
            self.mail = imaplib.IMAP4_SSL("imap.gmail.com")
            self.mail.login(self.user, self.password)
            self.mail.select("inbox") # Select inbox once upon connection for speed
            print("   [Conn] Connection successful.")
            return True
        except Exception as e:
            print(f"⚠️ Connection Error: {e}")
            self.mail = None
            return False

    def is_connected(self):
        """Checks if the client is currently connected."""
        if not self.mail:
            return False
        try:
            # A cheap way to check if the connection is alive
            self.mail.noop()
            return True
        except:
            return False

    def close(self):
        """Closes the connection gracefully."""
        if self.mail:
            try:
                self.mail.close()
                self.mail.logout()
            except:
                pass
        self.mail = None
        print("   [Conn] Connection closed.")

    def _create_folders(self):
        """Ensures quarantine folders exist."""
        for folder in ["Sentinel-FRAUD", "Sentinel-SUSPICIOUS"]:
            try:
                self.mail.create(folder)
            except:
                pass # Folder likely exists

    def get_baseline_uid(self):
        """Gets the UID of the next email to arrive, ensuring no old emails are processed."""
        if not self.is_connected():
            return -1
        
        last_uid = 0
        try:
            self._create_folders()
            # The response from SELECT contains UIDNEXT, which is the most reliable way
            # to get the UID that will be assigned to the next new message.
            status, data = self.mail.select("inbox") # Ensure we are in inbox for init
            if status == 'OK':
                # Try to get UIDNEXT first (most efficient)
                if 'UIDNEXT' in self.mail.untagged_responses:
                    uid_next = int(self.mail.untagged_responses['UIDNEXT'][0])
                    # The baseline is the UID before the next one
                    last_uid = uid_next - 1
                    print(f"   [Init] Found UIDNEXT: {uid_next}. Setting baseline to {last_uid}.")
                    return last_uid

                # Fallback: If UIDNEXT isn't available, find the max existing UID.
                # This is slower but very reliable.
                print("   [Init] UIDNEXT not found. Using fallback search to find max UID...")
                status, uids_data = self.mail.uid('search', None, 'ALL')
                if status == "OK" and uids_data[0]:
                    uid_list = [int(u) for u in uids_data[0].split()]
                    if uid_list:
                        last_uid = max(uid_list)
                        print(f"   [Init] Fallback successful. Max UID found: {last_uid}.")
                        return last_uid
                else:
                    # Inbox is empty
                    print("   [Init] Inbox appears empty. Baseline UID: 0")
                    return 0
        except Exception as e:
            print(f"   [Init] Error getting baseline UID: {e}")
        
        return -1

    def fetch_new_emails(self, last_seen_id):
        """Fetches all new emails since the last seen UID."""
        if not self.is_connected():
            return []

        # Optimization: Removed redundant 'select("inbox")' to speed up scanning loop
        status, messages = self.mail.uid('search', None, f'UID {last_seen_id+1}:*')
        if status != "OK" or not messages[0]:
            return []

        email_data_list = []
        new_ids = messages[0].split()
        for uid in new_ids:
            res, msg_data = self.mail.uid('fetch', uid, "(RFC822)")
            if res == 'OK':
                email_data_list.append({'uid': int(uid), 'data': msg_data})
        return email_data_list

    def move_email(self, uid, risk_level):
        """Moves an email to the appropriate quarantine folder."""
        if not self.is_connected():
            return False
        
        target_folder = None
        if risk_level == "High Risk":
            target_folder = "Sentinel-FRAUD"
        elif risk_level == "Medium Risk":
            target_folder = "Sentinel-SUSPICIOUS"

        if target_folder:
            self.mail.uid('COPY', uid, target_folder)
            self.mail.uid('STORE', uid, '+FLAGS', '\\Deleted')
            return True
        return False

def process_email_content(subject, body, sender):
    """Scans the email content for threats."""
    full_text = f"Subject: {subject} Body: {body}"
    print(f"[*] Analyzing email from {sender}...")

    # 1. Extract Target (URL or IP)
    target = None
    full_link = None
    
    url_match = re.search(r'(?:http[s]?://|www\.)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', full_text)
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', full_text)

    if url_match:
        full_link = url_match.group()
        if full_link.startswith("www."):
            full_link = "http://" + full_link
        target = urlparse(full_link).hostname
    elif ip_match:
        full_link = ip_match.group()
        target = full_link

    # 2. Scan Logic
    assessment = {}
    try:
        if target:
            print(f"    -> Found Link: {target}")
            print(f"    -> 🔍 Scanning target with Nmap (this may take a moment)...")
            scan_results = scan_target(target)
            open_ports = [port for port, _ in scan_results]
            assessment = analyze_risk(open_ports, full_text, full_link)
        else:
            print("    -> No link found, analyzing text keywords...")
            assessment = analyze_risk([], full_text, "Text Only")
    except Exception as e:
        print(f"    -> Error during scan: {e}")
        # Create a default assessment for scan failures
        assessment = {"level": "Medium Risk", "score": 50, "logs": [("error", f"Scan failed: {e}")]}

    assessment['target'] = target if target else "Email Content"
    return assessment

def send_mobile_alert(assessment, subject, sender):
    """Sends the analysis result to the mobile server."""
    payload = {
        "source": "GMAIL",
        "message": f"From: {sender}\nSubject: {subject}",
        "risk_level": assessment.get('level', 'Low Risk'),
        "score": assessment.get('score', 0),
        "target": assessment.get('target', 'Unknown')
    }
    try:
        requests.post(SERVER_URL, json=payload)
        print(f"    -> Mobile Alert Sent! Risk: {assessment.get('level', 'N/A')}")
    except Exception as e:
        print(f"    -> Failed to send mobile alert: {e}")

def start_monitoring():
    if "YOUR_APP_PASSWORD" in EMAIL_PASS or "YOUR_EMAIL" in EMAIL_USER:
        print("❌ ERROR: Please configure your Gmail credentials in gmail_scanner.py")
        print("   You must replace 'YOUR_EMAIL@gmail.com' and 'YOUR_APP_PASSWORD'.")
        print("   The password must be a 16-character App Password from Google.")
        return

    print("📧 SentinelAI Gmail Scanner is running...")
    print("   (Tip: Rename this file to .pyw to run in background without terminal)")

    client = GmailClient(EMAIL_USER, EMAIL_PASS)
    last_seen_id = -1

    # --- Dedicated Initialization Loop ---
    # This loop will not exit until a valid baseline UID is found.
    while last_seen_id == -1:
        if not client.is_connected():
            if not client.connect():
                print("   [Init] Connection failed. Retrying in 5 seconds...")
                time.sleep(5)
                continue
        
        last_seen_id = client.get_baseline_uid()
        
        if last_seen_id == -1:
            print("   [Init] Failed to establish baseline. Retrying in 5 seconds...")
            client.close() # Close the connection to try again fresh
            time.sleep(5)
        else:
            # --- DRAIN STEP ---
            # Explicitly check if any emails exist "after" our calculated baseline.
            # If they do (due to race conditions or UID mismatches), skip them.
            print("   [Init] Verifying baseline...")
            existing_overlap = client.fetch_new_emails(last_seen_id)
            if existing_overlap:
                max_overlap_uid = max(e['uid'] for e in existing_overlap)
                print(f"   [Init] Skipped {len(existing_overlap)} existing emails (UIDs {last_seen_id+1} to {max_overlap_uid}).")
                last_seen_id = max_overlap_uid

    print(f"   [Init] Baseline confirmed at UID {last_seen_id}. Waiting for NEW emails...")

    # --- Main Monitoring Loop ---
    while True:
        try:
            if not client.is_connected():
                # If connection is lost during monitoring, just reconnect.
                if not client.connect():
                    time.sleep(5)
                    continue

            new_emails = client.fetch_new_emails(last_seen_id)
            if not new_emails:
                time.sleep(1)
                continue

            print(f"\n[!] Found {len(new_emails)} new email(s). Processing...")
            moved_an_email = False

            for email_item in new_emails:
                last_seen_id = max(last_seen_id, email_item['uid'])
                msg = email.message_from_bytes(email_item['data'][0][1])

                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                
                sender = msg.get("From")

                # --- Whitelist Check ---
                if any(whitelisted_sender in sender for whitelisted_sender in TRUSTED_SENDERS):
                    print(f"[*] Skipping whitelisted sender: {sender}")
                    continue

                # --- Body Extraction ---
                text_content, html_content = "", ""
                for part in msg.walk():
                    if part.get_content_type() in ["text/plain", "text/html"]:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                decoded_payload = payload.decode(errors="ignore")
                                if part.get_content_type() == "text/plain":
                                    text_content += decoded_payload
                                else:
                                    html_content += decoded_payload
                        except Exception as e:
                            print(f"    -> Could not decode part: {e}")
                
                full_scan_text = html_content + " " + text_content

                # --- Analysis and Action ---
                assessment = process_email_content(subject, full_scan_text, sender)
                
                # Play sound alert for threats (This plays on the computer running the script)
                if assessment.get('level') == "High Risk":
                    print("    -> 🔊 Playing High Risk Alert Sound...")
                    winsound.Beep(1000, 1000) # Frequency 1000Hz, Duration 1000ms
                elif assessment.get('level') == "Medium Risk":
                    winsound.Beep(700, 500)

                send_mobile_alert(assessment, subject, sender)
                
                if client.move_email(str(email_item['uid']), assessment.get('level')):
                    print(f"    -> Moved email to quarantine.")
                    moved_an_email = True

            if moved_an_email:
                client.mail.expunge()

        except Exception as e:
            print(f"⚠️ Main loop error: {e}")
            client.close()
            time.sleep(3) # Wait before attempting to reconnect
            continue

if __name__ == "__main__":
    try:
        start_monitoring()
    except KeyboardInterrupt:
        print("\n🛑 Scanner stopped by user.")
