import sys
import os
import re
import subprocess
import requests
from urllib.parse import urlparse
import streamlit as st

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
    # The background service is now in its own file.
    background_service_path = os.path.join(os.path.dirname(__file__), '..', 'background_service.py')
    subprocess.Popen([sys.executable, background_service_path])
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