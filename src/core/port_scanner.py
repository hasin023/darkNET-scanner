import json
import sys
from scapy.all import sr, IP, TCP
import random

def run_port_scan(target_ip):
    src_port = random.randint(1024, 65535)
    scan_result = sr(IP(dst=target_ip) / TCP(sport=src_port, dport=range(1, 1025)), timeout=2, verbose=False)

    port_results = []
    for _, responded in scan_result[0]:
        port_results.append({
            "port": responded.sport,
            "service": responded[TCP].name,
            "state": responded[TCP].sprintf("%TCP.flags%"),
        })

    return json.dumps(port_results)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 port_scan.py <target_ip>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    results = run_port_scan(target_ip)
    print(results)
