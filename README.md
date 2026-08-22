# Network & Port Scanner

A concurrent, secure, and lightweight network port scanner written in Python. Optimized for penetration testing environments and network auditing.

## Technical and Architectural Choices

During the development of this tool, specific architectural decisions were made to ensure security, stability, and performance:

*   **Secure Memory Management (Context Managers):** Utilizing the `with socket.socket(...)` construct ensures automatic and deterministic closure of TCP sockets, preventing memory leaks even in cases of hanging connections or remote daemon crashes.
*   **Thread Explosion Prevention:** The implementation of a `ThreadPoolExecutor` with a logical upper bound (`min(len(ports), 100)`) prevents OS collapse or resource exhaustion (such as file descriptors) during massive scans.
*   **Security By-Design (XSS Mitigation):** Raw banners captured from remote services are sanitized using the standard `html` library (`html.escape`). This prevents Cross-Site Scripting (XSS) vulnerabilities when generating HTML reports, neutralizing malicious payloads provided by compromised hosts.
*   **Robust Validation:** The use of the `ipaddress` module ensures that only formally valid IPv4 networks are processed, preventing the execution of malformed or dangerous system commands (`ping`).
*   **Zero Dependencies:** The project relies exclusively on Python's standard library modules (`socket`, `subprocess`, `threading`, `concurrent.futures`, `html`, `json`), ensuring immediate execution without the need for virtual environments or `pip` installations.

## Command Line Interface (CLI) Usage

The tool is designed to be executed from the terminal with flexible options.

```bash
python scanner.py <network_cidr> [options]
```

### Positional Arguments
*   `network_cidr`: The target network in CIDR notation (e.g., `192.168.1.0/24`). (Required)

### Available Options
*   `-w, --workers <int>`: Maximum number of concurrent threads for host discovery (ping). Default: `50`. Increase with caution on large networks.
*   `-p, --ports <string>`: Comma-separated list of ports to scan. Default: `21, 22, 23, 80, 443, 3306, 8080`.
*   `-t, --timeout <float>`: Custom timeout (in seconds) for a single TCP connection. Default: `0.5`. Useful for slow networks or to reduce noise.
*   `-f, --format <html|json>`: Choose the output report format. Default: `html`.
*   `-o, --output <string>`: Output filename. If not specified, `report.html` or `report.json` will be used based on the chosen format.

## Usage Example

Scan a subnet with specific ports, an aggressive timeout, and output in JSON format:
```bash
python scanner.py 10.0.0.0/24 -w 100 -p "22,80,443,8080" -t 0.2 -f json -o target_scan.json