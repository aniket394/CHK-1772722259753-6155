import sys
import os
import re
import tkinter as tk
from tkinter import scrolledtext
from urllib.parse import urlparse
import requests

# Add project root to path to import modules
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

# Global UI elements
root = None
log_area = None
msg_entry = None

def log_to_ui(text):
    """Updates the log area in the UI."""
    if log_area:
        log_area.config(state='normal')
        log_area.insert(tk.END, text + "\n")
        log_area.see(tk.END)
        log_area.config(state='disabled')
        # Force UI update to prevent freezing during scan
        if root:
            root.update()

def show_popup(title, message, level):
    """Creates a notification banner at the top of the screen (Toast)."""
    # Determine style based on risk
    if level == "High Risk":
        bg_color = "#D32F2F"  # Red
        fg_color = "#FFFFFF"
    elif level == "Medium Risk":
        bg_color = "#FFA000"  # Amber
        fg_color = "#000000"
    else:
        bg_color = "#388E3C"  # Green
        fg_color = "#FFFFFF"

    # Create a borderless window
    notif = tk.Toplevel()
    notif.overrideredirect(True)
    notif.attributes("-topmost", True)
    notif.configure(bg=bg_color)

    # Position: Top Center (Notification Shade area)
    screen_width = notif.winfo_screenwidth()
    width = 450
    height = 90
    x_pos = (screen_width // 2) - (width // 2)
    y_pos = 40 
    notif.geometry(f"{width}x{height}+{x_pos}+{y_pos}")

    # UI Elements
    # 1. Header (App Name)
    header_frame = tk.Frame(notif, bg=bg_color)
    header_frame.pack(fill="x", padx=15, pady=(10, 2))
    
    tk.Label(header_frame, text="🛡️ Sentinel Mobile Guard", font=("Arial", 9, "bold"), bg=bg_color, fg=fg_color).pack(side="left")
    tk.Label(header_frame, text="now", font=("Arial", 8), bg=bg_color, fg=fg_color).pack(side="right")

    # 2. Content (Title + Body)
    content_frame = tk.Frame(notif, bg=bg_color)
    content_frame.pack(fill="both", padx=15)

    tk.Label(content_frame, text=title, font=("Arial", 11, "bold"), bg=bg_color, fg=fg_color, anchor="w").pack(fill="x")
    tk.Label(content_frame, text=message, font=("Arial", 10), bg=bg_color, fg=fg_color, anchor="w").pack(fill="x")

    # Dismiss logic
    def dismiss(event):
        notif.destroy()
    
    notif.bind("<Button-1>", dismiss)
    
    # Auto-close based on priority
    timeout = 4000
    if level == "High Risk":
        timeout = 10000  # 10 seconds for critical
    elif level == "Medium Risk":
        timeout = 7000   # 7 seconds for warning
    
    notif.after(timeout, notif.destroy)

def process_message(message):
    log_to_ui(f"\n[Processing] {message[:40]}...")
    
    # 1. Extract Target (Same logic as app.py)
    target = None
    full_link = None
    
    url_match = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message)
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)

    if url_match:
        full_link = url_match.group()
        target = urlparse(full_link).hostname
    elif ip_match:
        full_link = ip_match.group()
        target = full_link
    
    if not target:
        log_to_ui("[-] No link detected. Message safe.")
        return

    log_to_ui(f"[*] Scanning Target: {target}")
    
    # 2. Scan & Analyze
    # Note: This blocks the UI thread, but log_to_ui calls root.update() to keep it alive
    try:
        scan_results = scan_target(target)
        open_ports = [port for port, _ in scan_results]
        assessment = analyze_risk(open_ports, message, full_link)
    except PortScannerError:
        log_to_ui("❌ ERROR: Nmap is not installed on this system.")
        log_to_ui("   Please install it from https://nmap.org/download.html")
        show_popup("⚠️ SCAN FAILED", "Nmap executable not found.", "Medium Risk")
        return
    except Exception as e:
        log_to_ui(f"⚠️ An unexpected scan error occurred: {e}")
        show_popup("⚠️ SCAN FAILED", "An unexpected error occurred.", "Medium Risk")
        return
    
    risk_level = assessment['level']
    score = assessment['score']
    
    log_to_ui(f"[*] Analysis Complete. Risk: {risk_level} (Score: {score})")
    
    # Send to Mobile Server (Integration)
    try:
        payload = {
            "source": "SMS_SCANNER",
            "message": message,
            "risk_level": risk_level,
            "score": score,
            "target": target
        }
        requests.post("http://localhost:5001/trigger_alert", json=payload, timeout=1)
        log_to_ui("[+] Alert sent to Mobile Server.")
    except Exception as e:
        log_to_ui(f"[-] Failed to send to Mobile Server: {e}")

    # 3. Trigger Popup based on Priority Level
    if risk_level == "High Risk":
        show_popup("🚨 HIGH PRIORITY ALERT", f"Critical Threat Detected! (Score: {score})", risk_level)
    elif risk_level == "Medium Risk":
        show_popup("⚠️ SECURITY WARNING", f"Suspicious Content (Score: {score})", risk_level)
    else:
        show_popup("🛡️ SCAN COMPLETE", "Message Verified Safe.", risk_level)

def on_inject():
    msg = msg_entry.get()
    if not msg.strip():
        return
    process_message(msg)

if __name__ == "__main__":
    # Main Simulator Window
    root = tk.Tk()
    root.title("SentinelAI - Background Service Simulator")
    root.geometry("600x450")
    root.configure(bg="#f0f0f0")

    # Header
    header = tk.Label(root, text="Sentinel Mobile Guard\nBackground Service Simulator", 
                     font=("Helvetica", 14, "bold"), bg="#f0f0f0", fg="#333")
    header.pack(pady=15)

    # Input Section
    input_frame = tk.Frame(root, bg="#f0f0f0")
    input_frame.pack(pady=5)
    
    tk.Label(input_frame, text="Simulate Incoming SMS/Link:", bg="#f0f0f0").pack(anchor="w")
    msg_entry = tk.Entry(input_frame, width=50, font=("Consolas", 10))
    msg_entry.pack(pady=5)
    
    # Inject Button
    btn = tk.Button(root, text="⚡ Simulate Incoming Message", command=on_inject, 
                   bg="#d9534f", fg="white", font=("Arial", 10, "bold"), padx=10, pady=5)
    btn.pack(pady=10)

    # Logs
    tk.Label(root, text="Service Logs:", bg="#f0f0f0", font=("Arial", 9, "bold")).pack(anchor="w", padx=20)
    log_area = scrolledtext.ScrolledText(root, width=70, height=12, state='disabled', font=("Consolas", 9))
    log_area.pack(padx=20, pady=5)

    print("SentinelAI Background Service GUI Started...")
    root.mainloop()