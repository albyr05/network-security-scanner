import socket
import subprocess
import threading
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from generate_reports import generate_report


def ping(ip):  # receiving an ip address as input
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1000", ip],  # checking if the address is active or not
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


def scan_ports(ip, ports, timeout):  # FTP, SSH, telnet, HTTP, HTTPS, MySQL, webapp
    open_ports = []
    lock = threading.Lock()
    
    def check_port(port):
        banner = ""  # initialized BEFORE the try, so it always exists
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # looking for an IPv4 using TCP protocol
            sock.settimeout(timeout)  # wait the custom timeout (0.5 second default)
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
        help="IPv4 network in CIDR notation"
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
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default="21, 22, 23 , 80, 443, 3306, 8080",
        help="list of ports to scan (default: 21, 22, 23, 80, 443, 3306, 8080)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type = float,
        default=0.5,
        help="custom timeout to wait for each port"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    #input validation
    try: 
        network = ipaddress.ip_network(args.network_cidr, strict=False)
        if network.version != 4:
            print(f"Only IPv4 are supported")
            raise SystemExit(2)
        if str(network) != args.network_cidr:
            print(f"Network normalized to {str(network)}")

    except ValueError:
        print(f"Insert ip {args.network_cidr} isn't valid, make sure IPv4 valid cidr format")
        raise SystemExit(2)
    
    if args.workers < 1:
        print("--workers parameters must be at least 1")
        raise SystemExit(2)
    
    try:
        selected_ports = [int(p.strip()) for p in args.ports.split(",")]
        for p in selected_ports:
            if not (0 < p <= 65535): 
                print("ports number must range from 1 to 65535")
                raise SystemExit(2)
    except ValueError: 
        print("invalid port detected")
        raise SystemExit(2)
    if (args.timeout <= 0.0):
        print("timeout must be greater than 0")
        raise SystemExit(2)
    
    #check passed, can now scan network
    active_hosts = scan_network(network.hosts(), max_workers=args.workers)

    result = []
    selected_ports = sorted(set(selected_ports))
    for ip in active_hosts:
        open_ports = scan_ports(ip, selected_ports, args.timeout)
        result.append({
            "ip": str(ip),
            "ports": open_ports
        })
    generate_report(result, filename=args.output)