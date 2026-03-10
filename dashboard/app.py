import sys
import os
import re
import subprocess
import requests
from urllib.parse import urlparse

# -------------------------------------------------------------------------
# BACKGROUND SERVICE LOGIC (Runs when --bg-service flag is present)
# -------------------------------------------------------------------------
if "--bg-service" in sys.argv:
    import tkinter as tk
    from tkinter import scrolledtext
    
    # Fix path to import modules from parent directory
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    
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

    # Global UI elements for the background service
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
            if root:
                root.update()

    def show_popup(title, message, level):
        """Creates a notification banner at the top of the screen (Toast)."""
        if level == "High Risk":
            bg_color = "#D32F2F"  # Red
            fg_color = "#FFFFFF"
        elif level == "Medium Risk":
            bg_color = "#FFA000"  # Amber
            fg_color = "#000000"
        else:
            bg_color = "#388E3C"  # Green
            fg_color = "#FFFFFF"

        notif = tk.Toplevel()
        notif.overrideredirect(True)
        notif.attributes("-topmost", True)
        notif.configure(bg=bg_color)

        screen_width = notif.winfo_screenwidth()
        width = 450
        height = 90
        x_pos = (screen_width // 2) - (width // 2)
        y_pos = 40 
        notif.geometry(f"{width}x{height}+{x_pos}+{y_pos}")

        header_frame = tk.Frame(notif, bg=bg_color)
        header_frame.pack(fill="x", padx=15, pady=(10, 2))
        
        tk.Label(header_frame, text="🛡️ Sentinel Mobile Guard", font=("Arial", 9, "bold"), bg=bg_color, fg=fg_color).pack(side="left")
        tk.Label(header_frame, text="now", font=("Arial", 8), bg=bg_color, fg=fg_color).pack(side="right")

        content_frame = tk.Frame(notif, bg=bg_color)
        content_frame.pack(fill="both", padx=15)

        tk.Label(content_frame, text=title, font=("Arial", 11, "bold"), bg=bg_color, fg=fg_color, anchor="w").pack(fill="x")
        tk.Label(content_frame, text=message, font=("Arial", 10), bg=bg_color, fg=fg_color, anchor="w").pack(fill="x")

        def dismiss(event):
            notif.destroy()
        
        notif.bind("<Button-1>", dismiss)
        
        # Auto-close based on priority
        timeout = 4000
        if level == "High Risk":
            timeout = 10000
        elif level == "Medium Risk":
            timeout = 7000
        
        notif.after(timeout, notif.destroy)

    def process_message(message):
        log_to_ui(f"\n[Processing] {message[:40]}...")
        
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

    # Main Simulator Window
    root = tk.Tk()
    root.title("SentinelAI - Background Service Simulator")
    root.geometry("600x450")
    root.configure(bg="#f0f0f0")

    header = tk.Label(root, text="Sentinel Mobile Guard\nBackground Service Simulator", 
                     font=("Helvetica", 14, "bold"), bg="#f0f0f0", fg="#333")
    header.pack(pady=15)

    input_frame = tk.Frame(root, bg="#f0f0f0")
    input_frame.pack(pady=5)
    
    tk.Label(input_frame, text="Simulate Incoming SMS/Link:", bg="#f0f0f0").pack(anchor="w")
    msg_entry = tk.Entry(input_frame, width=50, font=("Consolas", 10))
    msg_entry.pack(pady=5)
    
    btn = tk.Button(root, text="⚡ Simulate Incoming Message", command=on_inject, 
                   bg="#d9534f", fg="white", font=("Arial", 10, "bold"), padx=10, pady=5)
    btn.pack(pady=10)

    tk.Label(root, text="Service Logs:", bg="#f0f0f0", font=("Arial", 9, "bold")).pack(anchor="w", padx=20)
    log_area = scrolledtext.ScrolledText(root, width=70, height=12, state='disabled', font=("Consolas", 9))
    log_area.pack(padx=20, pady=5)

    print("SentinelAI Background Service GUI Started...")
    root.mainloop()
    sys.exit()

import streamlit as st
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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

st.title("Sentinel Mobile Guard: Pre-installed Security Core")

# Sidebar: Background Service Control
st.sidebar.title("⚙️ System Controls")
st.sidebar.info("Launch the background simulation to test SMS/Notification alerts.")

if "bg_service_running" not in st.session_state:
    st.session_state.bg_service_running = False

if st.sidebar.button("🚀 Launch Background Service"):
    subprocess.Popen([sys.executable, __file__, "--bg-service"])
    st.session_state.bg_service_running = True
    st.sidebar.success("Background Service Started!")

message = st.text_area("Incoming Message Stream (SMS / Email / Link)")

if st.button("Analyze Message"):
    target = None
    full_link = None
    
    # 1. Try to find a URL
    url_match = re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', message)
    # 2. Try to find an IP address
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)

    if url_match:
        full_link = url_match.group()
        parsed = urlparse(full_link)
        target = parsed.hostname
    elif ip_match:
        full_link = ip_match.group()
        target = full_link
    elif "." in message and " " not in message:
        # Fallback for raw domains like "example.com"
        target = message
        full_link = message

    if not target:
        st.error("Could not find a valid Link or IP Address in the message.")
    else:
        st.write("Scanning target source:", target)
        try:
            results = scan_target(target)

            st.subheader("Open Ports")

            if not results:
                st.write("No open ports found")

            for port, service in results:
                st.write(f"Port {port} : {service}")

            open_ports = [port for port, _ in results]
            
            # --- Perform and Display Analysis ---
            assessment = analyze_risk(open_ports, message, full_link)
            
            st.subheader("🛡️ Real-time Protocol & Content Testing")
            if not assessment['logs']:
                st.success("✅ System Secure: No threats detected.")
            for severity, msg in assessment['logs']:
                if severity == "error": st.error(msg)
                elif severity == "warning": st.warning(msg)
                else: st.info(msg)

            st.markdown("---")
            st.subheader("🤖 AI Threat Prediction")
            risk_level = assessment['level']
            score = assessment['score']
            color = "red" if risk_level == "High Risk" else "orange" if risk_level == "Medium Risk" else "green"
            st.markdown(f"### Risk Score: **{score}/100**")
            st.markdown(f"### Classification: :{color}[**{risk_level}**]")
            if risk_level == "High Risk":
                st.error("🚨 **CRITICAL THREAT DETECTED**: Block sender and do not click links.")
            elif risk_level == "Medium Risk":
                st.warning("⚠️ **POTENTIAL THREAT**: Verify the sender before proceeding.")
            else:
                st.success("✅ **SAFE / LOW RISK**: No immediate threats detected.")

            # MOBILE ALERT INTEGRATION
            payload = {
                "message": message[:100] + "..." if len(message) > 100 else message,
                "risk_level": assessment['level'],
                "score": assessment['score'],
                "target": target
            }
            
            try:
                requests.post('http://localhost:5001/trigger_alert', json=payload, timeout=0.5)
                st.toast("📡 Alert sent to Mobile Device", icon="📲")
            except:
                pass # Fail silently
        except PortScannerError:
            st.error("❌ Nmap is not installed or not in your system's PATH.")
            st.error("SentinelAI requires the Nmap tool to perform network scans.")
            st.info("Please download and install it from the official website:")
            st.markdown("[https://nmap.org/download.html](https://nmap.org/download.html)")
        except Exception as e:
            st.error(f"An unexpected error occurred during the scan: {e}")