import sys
import os
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scanner.nmap_scan import scan_target
from parser.scan_parser import check_vulnerabilities

st.title("SentinelAI - AI Security Scanner")

ip = st.text_input("Enter Target IP Address")

if st.button("Start Scan"):

    st.write("Scanning target:", ip)

    results = scan_target(ip)

    st.subheader("Open Ports")

    if len(results) == 0:
        st.write("No open ports found")

    for port, service in results:
        st.write(f"Port {port} : {service}")

    open_ports = [port for port, _ in results]
    check_vulnerabilities(open_ports)