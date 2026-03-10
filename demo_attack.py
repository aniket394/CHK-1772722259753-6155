try:
    import requests
except ImportError:
    print("❌ Error: 'requests' library is missing.")
    print("   Run: pip install requests --break-system-packages")
    exit()

import time
import random

# Configuration
SERVER_URL = "http://localhost:5000/trigger_alert"

SCENARIOS = [
    {
        "risk_level": "High Risk",
        "score": 95,
        "message": "URGENT: Your bank account is suspended. Login immediately at http://192.168.1.50/login.php to verify.",
        "target": "192.168.1.50"
    },
    {
        "risk_level": "Medium Risk",
        "score": 45,
        "message": "Win a free iPhone! Click here to claim your prize: http://promo-winner.com/claim",
        "target": "promo-winner.com"
    },
    {
        "risk_level": "Low Risk",
        "score": 10,
        "message": "Hey, check out this article on cybersecurity: https://nmap.org/book/man.html",
        "target": "nmap.org"
    },
    {
        "risk_level": "High Risk",
        "score": 88,
        "message": "MALWARE DETECTED: Download this patch to fix your PC: http://patch-server.net/fix.exe",
        "target": "patch-server.net"
    }
]

print("==========================================")
print("🔥 SENTINEL AI - ATTACK SIMULATION MODE 🔥")
print("==========================================")
print(f"Target Server: {SERVER_URL}")
print("Press Ctrl+C to stop.\n")

while True:
    scenario = random.choice(SCENARIOS)
    print(f"🚀 Sending: {scenario['risk_level']} ({scenario['target']})...")
    
    try:
        requests.post(SERVER_URL, json=scenario)
        print("   ✅ Alert Sent!")
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Connection Failed: Cannot reach {SERVER_URL}")
        print("   (Make sure mobile_server.py is running in another terminal!)")
    except Exception as e:
        print(f"   ❌ Failed: {e}")
    
    print("   Waiting 8 seconds...\n")
    time.sleep(8)