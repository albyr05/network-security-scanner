import socket
import subprocess
import threading
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from generate_reports import generate_report


def ping(ip):  # receiving an ip address as input
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],  # checking if the address is active or not
        stdout=subprocess.DEVNULL,  # ignoring the output
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0  # return the result


# using a thread pool to make it faster without spawning unlimited threads
def scan_network(network_hosts, max_workers=50):
    active_hosts = []
    lock = threading.Lock()  # activating the lock key

    def check_host(ip):
        if ping(str(ip)):
            print(f"[+] Host attivo: {ip}")
            with lock:
                active_hosts.append(ip)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(check_host, network_hosts)  # waits for all to finish automatically

    return sorted(active_hosts)


def scan_ports(ip, ports=(21, 22, 23, 80, 443, 3306, 8080)):  # FTP, SSH, telnet, HTTP, HTTPS, MySQL, webapp
    open_ports = []
    lock = threading.Lock()
    
    def check_port(port):
        banner = ""  # initialized BEFORE the try, so it always exists
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # looking for an IPv4 using TCP protocol
            sock.settimeout(0.5)  # wait half a second
            result = sock.connect_ex((str(ip), port))  # trying the connection (three way handshake)

            if result == 0:  # the port was open
                print(f"[+] Port {port} aperta")
                try:
                    if port == 80:
                        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                        sock.send(request.encode())
                        answer = sock.recv(1024).decode("utf-8", errors="ignore").strip() #getting the answer of the raw http request
                        for l in answer.split("\n"):
                            if l.startswith("Server"):
                                banner = l.split(":")[1].strip()
                    else:
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip() #getting the banner of general ports
                    
                except Exception:
                    pass  # no banner received, that's fine — banner stays ""
                with lock:
                    open_ports.append({
                        "port": port,
                        "banner": banner if banner else "N/A"
                    })

            sock.close()  # closing the socket

        except Exception:
            pass

    # scanning ports for a single host in parallel too
    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        executor.map(check_port, ports)
        

    return sorted(open_ports, key=lambda p: p["port"])


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple LAN host/port scanner. Use ONLY on networks you own or are authorized to test."
    )
    parser.add_argument(
        "network_cidr",
        help="IPv4 network in CIDR notation”"
    )
    parser.add_argument(
        "-o", "--output",
        default="report.html",
        help="Output HTML report filename (default: report.html)"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=50,
        help="Max concurrent threads for host discovery (default: 50)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    active_hosts = scan_network(ipaddress.ip_network(args.network_cidr).hosts(), max_workers=args.workers)
    
    result = []
    for ip in active_hosts:
        ports = scan_ports(ip)
        result.append({
            "ip": str(ip),
            "ports": ports
        })
    generate_report(result, filename=args.output)