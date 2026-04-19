import socket 
import subprocess
import threading

def ping (ip):      #receiving an ip adress as input
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", ip],     #checking if the adress is active or not
        stdout=subprocess.DEVNULL,      # ignoring the output
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0   # return the result 

# using multithread to make it faster 
def scan_network (base_ip):
    print(f"Scanning network {base_ip}...\n")
    active_hosts = []
    threads = []
    lock = threading.Lock()     #activating the lock key

    def check_host (ip):
        if ping(ip):
            print(f"[+] Host attivo: {ip}")
            with lock:
                active_hosts.append(ip)

    for i in range (1, 255):
        ip = f"{base_ip}.{i}"
        t = threading.Thread(target=check_host, args=(ip,))     #opening a new thread

        threads.append(t)
        t.start()

    for t in threads:
        t.join()    #waiting all the threads to finish

    return active_hosts


def scan_ports(ip, ports = [21, 22, 23, 80, 443, 3306, 8080]): #FTP, SSH, telnet, HTTP, HTTPS , MySQL, webapp
    open_ports = []
    for port in ports:
        try: 
            sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM) #looking for an IPv4 using TCP protocol
            sock.settimeout(0.2) #wait a second
            result = sock.connect_ex((ip, port))    #trying the connection (three way handshake)
            
            if result == 0:     #the port was open
                print(f"[+] Port {port} aperta")
                try: 

                    banner = sock.recv(1024).decode("utf-8", errors = "ignore").strip()
                    if banner:
                        print(f"\t BANNER: {banner}")

                except: pass

                open_ports.append(port)

            sock.close()

        except: pass
    return open_ports


if __name__ == "__main__":
    base_ip = "172.20.10"
    result = scan_network(base_ip)
    print(f"\n{len(result)} active host found")
    print("\nScanning ports...")
    for ip in result:
        print(f"\n-- Host {ip}...\n")
        ports = scan_ports(ip)
        if len(ports) == 0:
            print("No ports open found for this host\n ")

    

