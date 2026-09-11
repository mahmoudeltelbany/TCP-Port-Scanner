import socket
import ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP",
    8443: "HTTPS",
}

DEFAULT_TIMEOUT = 0.5 
def _http_probe(sock, host):
    """Send a HEAD request over an already-connected socket and pull the
    Server header out of the response, if any."""
    request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    sock.sendall(request.encode())
    response = sock.recv(4096).decode(errors="ignore")

    if not response.startswith("HTTP/"):
        return None

    version = "Unknown"
    for line in response.splitlines():
        if line.lower().startswith("server:"):
            version = line.split(":", 1)[1].strip()
            break
    return version


def detect_service(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Try to identify the service and version running on a port.
    Makes a single connection per protocol attempt (instead of one
    connection for the open-check and another for detection).
    """

    # ---------------- SSH ----------------
    if port == 22 or port not in COMMON_SERVICES:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                banner = s.recv(1024).decode(errors="ignore").strip()

            if banner.startswith("SSH-"):
                parts = banner.split("-", 2)
                if len(parts) >= 3:
                    version_info = parts[2]
                    # Example: OpenSSH_9.6p1 Ubuntu-3ubuntu13
                    if version_info.startswith("OpenSSH_"):
                        version = version_info.split()[0].replace("OpenSSH_", "OpenSSH ")
                        return "SSH", version
                    return "SSH", version_info
        except OSError:
            pass

    # ---------------- HTTP ----------------
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            version = _http_probe(s, host)
        if version is not None:
            return "HTTP", version
    except OSError:
        pass

    # ---------------- HTTPS ----------------
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as s:
                s.settimeout(timeout)
                version = _http_probe(s, host)
        if version is not None:
            return "HTTPS", version
    except (OSError, ssl.SSLError):
        pass

    # ---------------- FTP / SMTP (both just greet with a "220 ..." banner) ----------------
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode(errors="ignore").strip()

        if banner.startswith("220"):
            return ("SMTP" if port == 25 else "FTP"), banner
    except OSError:
        pass

    # ---------------- Fallback to well-known port table ----------------
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port], "Unknown"

    return "Unknown", "Unknown"


def scan_port(host, port, timeout, use_sv):
    """Check a single port and optionally fingerprint the service on it.
    Returns None for closed ports so the caller can filter them out."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            is_open = True
    except OSError:
        is_open = False

    if not is_open:
        return {"port": port, "open": False}

    result = {"port": port, "open": True, "service": None, "version": None}
    if use_sv:
        service, version = detect_service(host, port, timeout=timeout)
        result["service"] = service
        result["version"] = version
    return result


def run_scan(host, ports, use_sv, specific_ports, timeout=DEFAULT_TIMEOUT, max_workers=200):
    """Scan every port concurrently and print results in port order."""
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(scan_port, host, port, timeout, use_sv): port
            for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            try:
                results[port] = future.result()
            except Exception as exc:
                results[port] = {"port": port, "open": False, "error": str(exc)}

    for port in sorted(results):
        r = results[port]
        if r["open"]:
            print(f"[+] Port {port} is OPEN")
            if use_sv:
                print(f"    Service: {r['service']}")
                print(f"    Version: {r['version']}")
        elif specific_ports:
            print(f"[-] Port {port} is CLOSED")


def parse_target(raw_target):
    """Parse the 'host' or 'host:port,port,...' [sv] input string."""
    target = raw_target.strip()

    use_sv = False
    if target.lower().endswith(" sv"):
        use_sv = True
        target = target[:-3].strip()

    if ":" in target:
        host, port_input = target.rsplit(":", 1)
        try:
            ports = [int(p.strip()) for p in port_input.split(",")]
        except ValueError:
            raise ValueError("Invalid port number.")
        specific_ports = True
    else:
        host = target
        ports = range(1025)
        specific_ports = False

    return host, ports, use_sv, specific_ports


def main():
    raw_target = input("Enter host or host:port,port,... [sv]: ")

    try:
        host, ports, use_sv, specific_ports = parse_target(raw_target)
    except ValueError as e:
        print(f"\n{e}")
        return

    if specific_ports:
        print(f"\nScanning selected ports on {host}...")
    else:
        print(f"\nScanning ports 0-1024 on {host}...")

    print(f"Started at: {datetime.now()}\n")
    print("-" * 120)

    run_scan(host, ports, use_sv, specific_ports)

    print("-" * 120)
    print(f"\nFinished at: {datetime.now()}")


if __name__ == "__main__":
    main()
