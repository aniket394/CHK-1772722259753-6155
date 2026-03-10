import sys
import os
import re
import requests
from flask import Flask, request
from urllib.parse import urlparse

# Ensure project root is in path for imports
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Fix Nmap Path on Windows
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

# --- CONFIGURATION ---
MOBILE_SERVER_URL = "http://localhost:5001/trigger_alert"
WEBHOOK_PORT = 5002  # Port to listen for Twilio messages

app = Flask(__name__)

@app.route('/sms', methods=['POST'])
def incoming_sms():
    """Receives incoming SMS from Twilio Webhook."""
    sender = request.form.get('From')
    body = request.form.get('Body')
    
    print(f"\n📩 New SMS from {sender}: {body}")
    
    # 1. Extract Target
    target = None
    full_link = None
    url_match = re.search(r'(?:http[s]?://|www\.)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    
    if url_match:
        full_link = url_match.group()
        if full_link.startswith("www."): full_link = "http://" + full_link
        target = urlparse(full_link).hostname
    
    # 2. Scan & Analyze
    try:
        if target:
            print(f"   [*] Scanning Link: {target}")
            scan_results = scan_target(target)
            open_ports = [port for port, _ in scan_results]
            assessment = analyze_risk(open_ports, body, full_link)
        else:
            print("   [*] Analyzing Text Content...")
            assessment = analyze_risk([], body, "Text Only")
            
        # 3. Forward to Mobile Server
        payload = {
            "source": f"SMS ({sender})",
            "message": body,
            "risk_level": assessment['level'],
            "score": assessment['score'],
            "target": target if target else "SMS Content"
        }
        requests.post(MOBILE_SERVER_URL, json=payload)
        print(f"   ✅ Alert sent to Mobile App. Risk: {assessment['level']}")

    except Exception as e:
        print(f"   ❌ Error processing SMS: {e}")

    return "OK", 200

if __name__ == "__main__":
    print(f"📡 Twilio SMS Scanner listening on port {WEBHOOK_PORT}...")
    print("   (Configure your Twilio Webhook URL to: http://<YOUR_IP>:5002/sms)")
    app.run(host='0.0.0.0', port=WEBHOOK_PORT)
