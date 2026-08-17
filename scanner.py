import socket
import subprocess
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor


def ping(ip):  # receiving an ip address as input
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],  # checking if the address is active or not
        stdout=subprocess.DEVNULL,  # ignoring the output
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0  # return the result


# using a thread pool to make it faster without spawning unlimited threads
def scan_network(base_ip, max_workers=50):
    print(f"Scanning network {base_ip}...\n")
    active_hosts = []
    lock = threading.Lock()  # activating the lock key

    def check_host(ip):
        if ping(ip):
            print(f"[+] Host attivo: {ip}")
            with lock:
                active_hosts.append(ip)

    ips = [f"{base_ip}.{i}" for i in range(1, 255)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(check_host, ips)  # waits for all to finish automatically

    return active_hosts


def scan_ports(ip, ports=(21, 22, 23, 80, 443, 3306, 8080)):  # FTP, SSH, telnet, HTTP, HTTPS, MySQL, webapp
    open_ports = []

    def check_port(port):
        banner = ""  # initialized BEFORE the try, so it always exists
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # looking for an IPv4 using TCP protocol
            sock.settimeout(0.5)  # wait half a second
            result = sock.connect_ex((ip, port))  # trying the connection (three way handshake)

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


def generate_report(results, filename="report.html"):
    html = """
    <html>
    <head>
        <title>Network Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
            h1 { color: #333; }
            .host { background: white; padding: 20px; margin: 20px 0; border-radius: 8px; }
            .port { margin: 5px 0; color: #444; }
            .open { color: green; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>Network Scan Report</h1>
    """

    for host in results:
        html += f"<div class='host'><h2>Host: {host['ip']}</h2>"
        if host['ports']:
            for p in host['ports']:
                html += f"<p class='port'><span class='open'>[+] Port {p['port']}</span> — Banner: {p['banner']}</p>"
        else:
            html += "<p>No open ports found</p>"
        html += "</div>"

    html += "</body></html>"

    with open(filename, "w") as f:
        f.write(html)

    print(f"\n[+] Report saved as {filename}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simple LAN host/port scanner. Use ONLY on networks you own or are authorized to test."
    )
    parser.add_argument(
        "base_ip",
        help="First three octets of the network, e.g. 172.20.10 (scans .1 to .254)"
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

    active_hosts = scan_network(args.base_ip, max_workers=args.workers)
    result = []
    for ip in active_hosts:
        ports = scan_ports(ip)
        result.append({
            "ip": ip,
            "ports": ports
        })
    generate_report(result, filename=args.output)