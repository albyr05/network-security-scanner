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

if __name__ == "__main__":
    base_ip = "172.21.73"
    result = scan_network(base_ip)
    print(f"\n{len(result)} active host found")

