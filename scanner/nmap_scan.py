import nmap

def scan_target(ip):

    scanner = nmap.PortScanner()

    scanner.scan(ip, '1-10000')
    results = []

    for host in scanner.all_hosts():

        for proto in scanner[host].all_protocols():

            ports = scanner[host][proto].keys()

            for port in ports:

                service = scanner[host][proto][port]['name']

                results.append((port, service))

    return results