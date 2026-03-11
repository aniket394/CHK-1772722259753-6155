def analyze_risk(open_ports, message, link):
    """
    Analyzes scan results and message content to calculate a risk score.
    """
    score = 0
    logs = []
    reasons = []
    
    # 1. Port Analysis (Network Threats)
    dangerous_ports = {
        21: "FTP (File Transfer - Insecure)",
        23: "Telnet (Unencrypted - High Risk)",
        445: "SMB (Ransomware Vector)",
        3389: "RDP (Remote Desktop)",
    }
    
    for port, service in open_ports:
        if port in dangerous_ports:
            score += 25
            logs.append(("warning", f"Open Port {port}: {dangerous_ports[port]}"))
            reasons.append(f"Dangerous Port {port} Open")
    
    # 2. Content Analysis (Phishing/Social Engineering)
    msg_lower = message.lower()
    phishing_keywords = ["urgent", "verify", "password", "bank", "suspended", "login", "update account"]
    
    found_keywords = [w for w in phishing_keywords if w in msg_lower]
    if found_keywords:
        score += 35
        logs.append(("warning", f"Phishing keywords: {', '.join(found_keywords)}"))
        reasons.append("Phishing Keywords Detected")
        
    # 3. Link Analysis (Obfuscation)
    if link:
        if "@" in link: # malicious@site.com pattern
            score += 40
            reasons.append("URL contains '@' (Obfuscation technique)")
        if link.count('.') > 3: # very.long.subdomain.com
            score += 15
            reasons.append("Suspiciously long subdomain")
            
    # Cap Score
    score = min(score, 100)
    
    level = "Low Risk"
    if score >= 70:
        level = "High Risk"
    elif score >= 30:
        level = "Medium Risk"
        
    return {
        "level": level, "score": score, "logs": logs, "reasons": reasons
    }