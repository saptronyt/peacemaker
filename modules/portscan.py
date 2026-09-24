"""Port scanner: fast TCP connect scanning with service detection (banner grabbing)."""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MS-RPC",
    137: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 9200}

PROBES = {
    "http": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "generic": b"\r\n",
}


def _scan_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except (socket.timeout, OSError):
        return port, False


def scan_host(host, ports, timeout=1.0, threads=100, quiet=False):
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(_scan_port, host, p, timeout) for p in ports]
        for future in futures:
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                if not quiet:
                    service = COMMON_PORTS.get(port, "unknown")
                    print(f"  [+] {host}:{port:<6} open  ({service})")
    return sorted(open_ports)


def banner_grab(host, port, timeout=3.0):
    """Connect and read the service banner to identify the software + version."""
    try:
        probe = PROBES["http"] if port in HTTP_PORTS else PROBES["generic"]
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendall(probe)
            except OSError:
                pass
            chunks = []
            sock.settimeout(1.5)
            for _ in range(4):
                try:
                    data = sock.recv(2048)
                except (socket.timeout, OSError):
                    break
                if not data:
                    break
                chunks.append(data)
        raw = b"".join(chunks)
        return raw[:4096].decode("utf-8", errors="replace").strip()
    except (socket.timeout, OSError):
        return ""


def grab_all(host, ports, timeout=3.0, threads=50):
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(banner_grab, host, p, timeout): p for p in ports}
        for future in futures:
            port = futures[future]
            try:
                banner = future.result()
            except Exception:
                banner = ""
            results[port] = banner
    return results


def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def port_names(open_ports):
    return {p: COMMON_PORTS.get(p, "unknown") for p in open_ports}
