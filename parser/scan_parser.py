import streamlit as st

def check_vulnerabilities(open_ports):
    vulnerabilities = {
        21: "FTP - Weak authentication possible",
        22: "SSH - Possible brute force attack",
        23: "Telnet - Insecure protocol",
        80: "HTTP - Web server vulnerabilities",
        445: "SMB - Ransomware risk",
        8000: "HTTP service – Possible directory exposure",
        8501: "Streamlit server – Debug exposure risk"
    }

    for port in open_ports:
        if port in vulnerabilities:
            st.warning(f"Port {port}: {vulnerabilities[port]}")