import streamlit as st
from typing import List

KNOWN_VULNERABILITIES = {
    21: ("Multimedia Port (FTP) - Testing for Fake/Malicious Files...", "warning", 30),
    22: ("Admin Port (SSH) - Testing for Unauthorized Access Scripts...", "warning", 20),
    23: ("Legacy Port (Telnet) - Testing for Unencrypted Data Leaks...", "error", 40),
    25: ("Email Port (SMTP) - Testing for Phishing & Spam Content...", "warning", 20),
    80: ("Web Port (HTTP) - Testing for Fake Websites & Malicious Links...", "warning", 10),
    110: ("Email Port (POP3) - Testing for Insecure Message Retrieval...", "error", 25),
    143: ("Email Port (IMAP) - Testing for Message Synchronization Attacks...", "warning", 20),
    443: ("Secure Web (HTTPS) - Verifying SSL Certificates & Content Trust...", "info", 5),
    445: ("File Share (SMB) - Testing for Ransomware & Fake Files...", "error", 30),
    465: ("Secure Email (SMTPS) - Testing Encrypted Message Content...", "warning", 10),
    587: ("Email Submission - Testing Outbound Message Validity...", "warning", 10),
    993: ("Secure Email (IMAPS) - Testing Encrypted Sync Integrity...", "warning", 10),
    995: ("Secure Email (POP3S) - Testing Encrypted Download Integrity...", "warning", 10),
    3389: ("Remote Desktop (RDP) - Testing for Screen Capture Risks...", "error", 40),
    5555: ("Android Debug (ADB) - Testing for Unauthorized App Installs...", "error", 45),
    5900: ("Screen Share (VNC) - Testing for Visual Spyware...", "error", 40),
    8000: ("Web Service - Testing for Unverified API Endpoints...", "warning", 15),
    8080: ("Proxy Server - Testing for Man-in-the-Middle Attacks...", "warning", 15),
    8501: ("App Server - Testing for Exposed Debug Interfaces...", "warning", 10)
}

PHISHING_KEYWORDS = [
    "urgent", "verify", "account", "login", "password", "bank", "free", 
    "winner", "prize", "suspended", "unusual activity", "confirm", "security alert",
    "lottery", "btc", "crypto", "investment"
]

DANGEROUS_EXTENSIONS = ['.apk', '.exe', '.zip', '.rar', '.sh', '.bin']

def analyze_risk(open_ports: List[int], message_content: str, target: str) -> dict:
    """Core AI Logic: Calculates risk score and returns analysis data."""
    total_score = 0
    logs = [] # Stores log messages (severity, text)

    # 1. Protocol/Port Analysis
    for port in open_ports:
        if port in KNOWN_VULNERABILITIES:
            test_name, severity, weight = KNOWN_VULNERABILITIES[port]
            total_score += weight
            logs.append((severity, f"Port {port}: {test_name} (+{weight} Risk)"))
        else:
            weight = 5
            total_score += weight
            logs.append(("info", f"Port {port}: Unknown Protocol (+{weight} Risk)"))

    # 2. Content & Fraud Analysis (Fake Content Detection)
    content_risk = 0
    suspicious_words = [word for word in PHISHING_KEYWORDS if word in message_content.lower()]
    
    if suspicious_words:
        content_risk += 40
        logs.append(("warning", f"⚠️ FRAUD DETECTED: Keywords found: {', '.join(suspicious_words)}"))
    
    if any(target.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
        content_risk += 50
        logs.append(("error", f"🚨 MALWARE ALERT: Dangerous file type ({target.split('.')[-1]})."))
    
    total_score += content_risk

    # 3. AI Risk Prediction
    risk_level = "Low Risk"
    if total_score > 60:
        risk_level = "High Risk"
    elif total_score > 30:
        risk_level = "Medium Risk"

    return {
        "score": total_score,
        "level": risk_level,
        "logs": logs
    }

def check_vulnerabilities(open_ports: List[int], message_content: str, target: str) -> None:
    """Dashboard Wrapper: Displays analysis results in Streamlit."""
    assessment = analyze_risk(open_ports, message_content, target)
    
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
        st.error("🚨 **CRITICAL THREAT DETECTED**")
        st.write("This source contains fake content or dangerous protocols. **Do not click links or download files.**")
        st.write("**Action:** Block sender and disconnect from this network source.")
    elif risk_level == "Medium Risk":
        st.warning("⚠️ **POTENTIAL THREAT**")
        st.write("The target exposes services or content that requires caution.")
        st.write("**Action:** Verify the sender identity before proceeding.")
    else:
        st.success("✅ **SAFE / LOW RISK**")
        st.write("No fraud or protocol vulnerabilities detected.")
        st.write("**Action:** Safe to proceed.")