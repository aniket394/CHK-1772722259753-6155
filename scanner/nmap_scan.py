import nmap
import sys

def scan_target(target):
    """
    Scans a target IP/Domain for open ports using Nmap.
    Returns a list of tuples: [(port, service_name), ...]
    """
    nm = nmap.PortScanner()
    try:
        # -T4: Faster timing, -F: Fast mode (Top 100 ports)
        nm.scan(target, arguments='-T4 -F') 
        
        # Get the first resolved IP
        hosts = nm.all_hosts()
        if not hosts:
            return []
        
        ip = hosts[0]
        if 'tcp' not in nm[ip]:
            return []
            
        open_ports = []
        for port in nm[ip]['tcp']:
            state = nm[ip]['tcp'][port]['state']
            if state == 'open':
                service = nm[ip]['tcp'][port]['name']
                open_ports.append((port, service))
        return open_ports
    except Exception:
        return []