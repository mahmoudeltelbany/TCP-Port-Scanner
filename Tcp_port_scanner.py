import socket
import ssl
from datetime import datetime


# Common service names
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
    8443: "HTTPS"
}


def detect_service(host, port, timeout=.0002):
    """
    Try to identify the service and version running on a port.  
    """

    # ---------------- SSH ----------------
    if port == 22 or port not in COMMON_SERVICES:

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))

            banner = s.recv(1024).decode(errors="ignore").strip()

            s.close()

            if banner.startswith("SSH-"):

                parts = banner.split("-", 2)

                if len(parts) >= 3:
                    version_info = parts[2]

                    # Example:
                    # OpenSSH_9.6p1 Ubuntu-3ubuntu13

                    if version_info.startswith("OpenSSH_"):
                        version = version_info.split()[0]
                        version = version.replace("OpenSSH_", "OpenSSH ")

                        return "SSH", version

                    return "SSH", version_info

        except:
            pass

    # ---------------- HTTP ----------------
    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        s.connect((host, port))

        request = (
            f"HEAD / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        s.sendall(request.encode())

        response = s.recv(4096).decode(errors="ignore")

        s.close()

        if response.startswith("HTTP/"):

            service = "HTTP"
            version = "Unknown"

            for line in response.splitlines():

                if line.lower().startswith("server:"):

                    version = line.split(":", 1)[1].strip()
                    break

            return service, version

    except:
        pass

    # ---------------- HTTPS ----------------
    try:

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(timeout)

        raw_socket.connect((host, port))

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        s = context.wrap_socket(
            raw_socket,
            server_hostname=host
        )

        request = (
            f"HEAD / HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        s.sendall(request.encode())

        response = s.recv(4096).decode(errors="ignore")

        s.close()

        if response.startswith("HTTP/"):

            version = "Unknown"

            for line in response.splitlines():

                if line.lower().startswith("server:"):

                    version = line.split(":", 1)[1].strip()
                    break

            return "HTTPS", version

    except:
        pass

    # ---------------- FTP ----------------
    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        s.connect((host, port))

        banner = s.recv(1024).decode(errors="ignore").strip()

        s.close()

        if banner.startswith("220"):

            return "FTP", banner

    except:
        pass

    # ---------------- SMTP ----------------
    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        s.connect((host, port))

        banner = s.recv(1024).decode(errors="ignore").strip()

        s.close()

        if banner.startswith("220"):

            return "SMTP", banner

    except:
        pass

    # ---------------- Known service ----------------
    if port in COMMON_SERVICES:

        return COMMON_SERVICES[port], "Unknown"

    return "Unknown", "Unknown"


# =========================================================
# Main Program
# =========================================================

target = input("Enter host or host:port,port,... [sv]: ").strip()


# Check if service/version detection is requested
use_sv = False

if target.lower().endswith(" sv"):

    use_sv = True
    target = target[:-3].strip()


# =========================================================
# Parse host and ports
# =========================================================

if ":" in target:

    host, port_input = target.rsplit(":", 1)

    try:
        ports = [
            int(port.strip())
            for port in port_input.split(",")
        ]

    except ValueError:

        print("\nInvalid port number.")
        exit()

    specific_ports = True

    print(f"\nScanning selected ports on {host}...")

else:

    host = target
    ports = range(1025)

    specific_ports = False

    print(f"\nScanning ports 0-1024 on {host}...")


# =========================================================
# Scan
# =========================================================

print(f"Started at: {datetime.now()}\n")
print("-" * 120)


for port in ports:

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Timeout = 1 second
    s.settimeout(.0002)

    result = s.connect_ex((host, port))

    # -----------------------------------------------------
    # OPEN
    # -----------------------------------------------------

    if result == 0:

        print(f"[+] Port {port} is OPEN")

        # Service / Version Detection
        if use_sv:

            service, version = detect_service(
                host,
                port,
                timeout=.0002
            )

            print(f"    Service: {service}")
            print(f"    Version: {version}")

    # -----------------------------------------------------
    # CLOSED
    # -----------------------------------------------------

    elif specific_ports:

        print(f"[-] Port {port} is CLOSED")

    s.close()


print("-" * 120)
print(f"\nFinished at: {datetime.now()}")