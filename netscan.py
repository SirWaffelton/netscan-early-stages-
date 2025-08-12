"""
Network Device Scanner (Sprints 1–5 consolidated)

What it does:
- Detects your local IPv4 network and ping-sweeps it to find live hosts
- Reads ARP table to map IP -> MAC and guess vendor (optional manuf library)
- Checks a set of common ports per host (quick TCP connect)
- Optionally grabs a tiny HTTP/HTTPS banner (Server header)
- Resolves hostnames (reverse DNS / NetBIOS)
- Optional: skip scanning your own host (to avoid local-only confusion)
- Optional: save to JSON/CSV, and diff against a previous JSON
- Optional: only show hosts with open ports on screen (--only-open)

Ethics: Only scan networks you own or have explicit permission to test.
"""

import argparse
import csv
import ipaddress
import json
import platform
import re
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional

# Optional deps:
#   psutil: interface detection (pip install psutil)
#   pythonping: cleaner ping on Windows (pip install pythonping)
#   manuf: richer MAC vendor lookups (pip install manuf)
try:
    import psutil  # type: ignore
except ImportError:
    psutil = None

try:
    from pythonping import ping as _py_ping  # type: ignore
except Exception:
    _py_ping = None

try:
    from manuf import manuf  # type: ignore
    _MAC_PARSER = manuf.MacParser()
except Exception:
    _MAC_PARSER = None

IS_WINDOWS = platform.system().lower().startswith("windows")

# Mode presets
FAST_PORTS = [22, 80, 443, 445, 3389]
THOROUGH_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 631, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000
]
CONNECT_TIMEOUT = 0.6  # seconds per port

# Ports we consider “webby” for banner grabbing
HTTP_PORTS = [80, 8000, 8080, 8081, 3000, 5000, 8888]
HTTPS_PORTS = [443, 8443, 9443, 10443]

# Small offline OUI vendor hints (first 3 bytes of MAC). manuf is better if installed.
OUI_HINTS = {
    "08:00:27": "VirtualBox", "00:50:56": "VMware", "52:54:00": "QEMU/KVM",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Apple", "a4:83:e7": "Apple",
    "f0:27:65": "Ubiquiti", "68:ff:7b": "Ubiquiti", "3c:5a:b4": "Microsoft",
    "f4:f5:e8": "Google", "28:cf:e9": "Google", "b4:fb:e4": "Amazon",
    "ac:63:be": "Amazon", "d8:bb:2c": "TP-Link", "f4:28:53": "TP-Link",
    "2c:f0:5d": "Samsung", "fc:db:b3": "Samsung", "00:1a:2b": "Cisco", "00:1b:54": "Cisco",
}

# ------------- Helper: choose network to scan -------------
def detect_ipv4_interfaces():
    """
    Return [(name, ip, netmask)] for active IPv4 interfaces.
    Requires psutil; otherwise returns [] and we’ll ask the user.
    """
    results = []
    if not psutil:
        return results
    for name, addrs in psutil.net_if_addrs().items():
        ip = None
        nm = None
        for a in addrs:
            fam_name = getattr(a.family, "name", str(a.family))
            if fam_name in ("AF_INET", "AddressFamily.AF_INET"):
                ip = a.address
                nm = a.netmask
        if ip and nm and not ip.startswith(("127.", "169.254.")):
            results.append((name, ip, nm))
    return results

def choose_network():
    """
    Let the user pick an interface; build an IPv4Network from IP/netmask.
    If big (e.g., /16), offer to narrow to /24 for speed.
    """
    cands = detect_ipv4_interfaces()
    if not cands:
        print("Could not auto-detect interfaces. Enter CIDR:")
        cidr = input("> ").strip()
        return ipaddress.IPv4Network(cidr, strict=False)
    print("Detected IPv4 interfaces:")
    for idx, (name, ip, nm) in enumerate(cands, 1):
        print(f"{idx}) {name}: {ip}/{nm}")
    choice = input(f"Choose interface 1-{len(cands)} (default 1): ").strip()
    idx = 1 if not choice else max(1, min(len(cands), int(choice)))
    _, ip, nm = cands[idx - 1]

    net = ipaddress.IPv4Network((ip, nm), strict=False)
    if net.num_addresses > 256:
        narrow = input(f"Network {net} has {net.num_addresses} addresses. Narrow to /24 at {ip}/24? [Y/n]: ").strip().lower()
        if narrow in ("", "y", "yes"):
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    print(f"Scanning network: {net}")
    return net

# ------------- Host discovery: ping sweep -------------
def ping_once(ip: str, timeout_ms: int = 400) -> bool:
    """
    True if host replies quickly to one ICMP echo.
    Windows: use pythonping if available (no noisy subprocesses).
    Linux/Kali: shell out to ping with 1 packet.
    """
    if IS_WINDOWS and _py_ping is not None:
        try:
            resp = _py_ping(ip, count=1, timeout=timeout_ms / 1000.0, size=32, verbose=False)
            return resp.success()
        except Exception:
            return False
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        else:
            sec = max(1, int(round(timeout_ms / 1000)))
            cmd = ["ping", "-c", "1", "-W", str(sec), "-n", ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def sweep(network: ipaddress.IPv4Network, workers: Optional[int] = None):
    """
    Ping all usable IPs in the network concurrently.
    Returns a sorted list of live IP strings.
    """
    hosts = [str(h) for h in network.hosts()]
    if not workers:
        workers = 50 if IS_WINDOWS else 100  # Windows prefers lower concurrency
    live = []
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts) or 1)) as exe:
        futs = {exe.submit(ping_once, ip): ip for ip in hosts}
        done = 0
        for fut in as_completed(futs):
            ip = futs[fut]
            ok = False
            try:
                ok = fut.result()
            except Exception:
                ok = False
            if ok:
                live.append(ip)
            done += 1
            if done % 32 == 0:
                print(f"…progress: {done}/{len(hosts)}")
    live.sort(key=lambda s: tuple(map(int, s.split("."))))
    return live

# ------------- ARP + vendor -------------
def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) == 6:
        parts = [p.zfill(2) for p in parts]
        return ":".join(parts)
    return mac

def get_arp_table(network: ipaddress.IPv4Network) -> Dict[str, str]:
    """
    Parse ARP table into {ip: mac} for this network.
    Windows: arp -a
    Linux: ip neigh show
    """
    mapping: Dict[str, str] = {}
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
            for line in out.splitlines():
                m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{11,})\s+\w+\s*$", line)
                if not m:
                    continue
                ip, mac = m.group(1), normalize_mac(m.group(2))
                try:
                    if ipaddress.IPv4Address(ip) in network and mac != "ff:ff:ff:ff:ff:ff":
                        mapping[ip] = mac
                except Exception:
                    continue
        else:
            out = subprocess.check_output(["ip", "neigh", "show"], text=True, errors="ignore")
            for line in out.splitlines():
                # Example: 192.287.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                m = re.match(
                    r"^\s*(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+(?:\s+lladdr\s+([0-9a-fA-F:]{17}))?\s+([A-Z]+)",
                    line,
                )
                if not m:
                    continue
                ip, mac, state = m.group(1), m.group(2), m.group(3)
                if mac:
                    mac = normalize_mac(mac)
                if state in ("INCOMPLETE", "FAILED"):
                    continue
                try:
                    if ipaddress.IPv4Address(ip) in network and mac:
                        mapping[ip] = mac
                except Exception:
                    continue
    except Exception:
        pass
    return mapping

def find_self_ip_and_mac(network: ipaddress.IPv4Network) -> Tuple[Optional[str], Optional[str]]:
    """
    Use psutil to find our own IPv4 address/MAC on the scanned network.
    """
    if not psutil:
        return None, None
    for _, addrs in psutil.net_if_addrs().items():
        ipv4 = None
        mac = None
        mac_family = getattr(psutil, "AF_LINK", None)
        for a in addrs:
            fam_name = getattr(a.family, "name", str(a.family))
            if fam_name in ("AF_INET", "AddressFamily.AF_INET"):
                ipv4 = a.address
            if (mac_family and a.family == mac_family) or fam_name in ("AF_LINK", "AF_PACKET"):
                mac = a.address
        if ipv4 and ipaddress.IPv4Address(ipv4) in network:
            return ipv4, normalize_mac(mac) if mac else None
    return None, None

def vendor_lookup(mac: str) -> str:
    """
    Best effort vendor string. If manuf is installed, use its DB; else fall back to OUI_HINTS.
    """
    if not mac or mac == "—":
        return "—"
    try:
        if _MAC_PARSER:
            v = _MAC_PARSER.get_manuf(mac)
            if v:
                return v
        prefix = mac[:8] if len(mac) >= 8 else mac
        return OUI_HINTS.get(prefix, "Unknown")
    except Exception:
        return "Unknown"

# ------------- Quick service checks + banners -------------
def check_port(ip: str, port: int, timeout: float) -> bool:
    """
    Basic TCP connect scan for one port (non-invasive).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0  # 0 = open
    except Exception:
        return False

def quick_service_check(ip: str, ports: List[int], timeout: float) -> List[int]:
    """
    Check a small list of ports quickly (sequential per host).
    """
    opens: List[int] = []
    for p in ports:
        if check_port(ip, p, timeout=timeout):
            opens.append(p)
    return opens

def scan_services_for_all(hosts: List[str], ports: List[int], timeout: float, workers: int = 64) -> Dict[str, List[int]]:
    """
    Parallelize quick_service_check across hosts.
    """
    results: Dict[str, List[int]] = {}
    if not hosts:
        return results
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as exe:
        futs = {exe.submit(quick_service_check, ip, ports, timeout): ip for ip in hosts}
        done = 0
        total = len(hosts)
        for fut in as_completed(futs):
            ip = futs[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = []
            done += 1
            if done % 5 == 0 or done == total:
                print(f"…service scan progress: {done}/{total}")
    return results

def http_banner(ip: str, port: int, use_tls: bool, timeout: float = 1.2) -> str:
    """
    Send a tiny HTTP HEAD and return the status line + Server header if present.
    Ignores TLS cert validation (lab use).
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=ip)
        req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netscan/1.0\r\nConnection: close\r\n\r\n".encode("ascii")
        sock.sendall(req)
        sock.settimeout(timeout)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
        sock.close()
        text = data.decode("iso-8859-1", errors="ignore")
        first = text.split("\r\n", 1)[0].strip() if text else "no response"
        server = None
        for line in text.split("\r\n"):
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break
        return f"{first} | Server: {server}" if server else first
    except ssl.SSLError as e:
        return f"TLS error: {e.__class__.__name__}"
    except Exception as e:
        return f"no banner ({e.__class__.__name__})"

def grab_banners(open_map: Dict[str, List[int]], timeout: float = 1.2, workers: int = 64) -> Dict[str, Dict[int, str]]:
    """
    For any host with web ports open, grab a short banner per port.
    Returns: {ip: {port: banner_str}}
    """
    banners: Dict[str, Dict[int, str]] = {}
    tasks = []
    for ip, ports in open_map.items():
        for p in ports:
            if p in HTTP_PORTS or p in HTTPS_PORTS:
                tasks.append((ip, p, p in HTTPS_PORTS))
    if not tasks:
        return banners
    with ThreadPoolExecutor(max_workers=min(workers, len(tasks))) as exe:
        futs = {exe.submit(http_banner, ip, p, tls, timeout): (ip, p) for (ip, p, tls) in tasks}
        done = 0
        total = len(tasks)
        for fut in as_completed(futs):
            ip, p = futs[fut]
            try:
                result = fut.result()
            except Exception as e:
                result = f"error ({e.__class__.__name__})"
            banners.setdefault(ip, {})[p] = result
            done += 1
            if done % 10 == 0 or done == total:
                print(f"…banner grab progress: {done}/{total}")
    return banners

def infer_type(open_ports: List[int], vendor: str) -> str:
    """
    Heuristics: map open ports + vendor hints -> rough device type.
    """
    v = (vendor or "").lower()
    has = lambda x: x in open_ports

    if any(k in v for k in ("arris", "arrisgro")):
        return "Gateway/Router (web mgmt)" if any(has(p) for p in (80, 443, 8443)) else "Gateway/Router"
    if any(k in v for k in ("ubiquiti", "cisco", "tp-link", "tplink", "netgear")):
        return "Network gear (web mgmt)" if any(has(p) for p in (80, 443, 8443)) else "Network gear"

    if has(3389):
        return "Windows (RDP)"
    if has(445) and not has(3389):
        return "Windows/SMB or NAS/Printer"
    if has(22) and any(has(p) for p in (80, 443, 8080, 8443)):
        return "Linux/UNIX + Web service"
    if has(22):
        return "Linux/UNIX (SSH)"
    if any(has(p) for p in (80, 443, 8080, 8443)):
        return "Web device"
    return "Alive (no common services open)"

# ------------- Sprint 5 additions: names, skip-self, diff -------------
def reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

def netbios_name(ip: str) -> Optional[str]:
    """
    Try to fetch NetBIOS name.
    Windows: nbtstat -A <ip>
    Linux: nmblookup -A <ip> (install: sudo apt -y install samba-common-bin)
    """
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["nbtstat", "-A", ip], text=True, errors="ignore")
            # NAMEHERE        <00>  UNIQUE      Registered
            for line in out.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_\-]{1,15})\s+<00>\s+UNIQUE\s+Registered", line)
                if m:
                    return m.group(1)
        else:
            out = subprocess.check_output(["nmblookup", "-A", ip], text=True, errors="ignore")
            # NAMEHERE <00> - <ACTIVE>
            for line in out.splitlines():
                m = re.match(r"^\s*([A-Za-z0-9_\-]{1,15})\s+<00>\s+[-BH]\s+<ACTIVE>", line)
                if m:
                    return m.group(1)
    except Exception:
        return None
    return None

def resolve_names(hosts: List[str], workers: int = 32) -> Dict[str, str]:
    """
    Resolve reverse DNS first; if missing, fall back to NetBIOS.
    Returns {ip: name}
    """
    names: Dict[str, str] = {}
    if not hosts:
        return names
    def _resolve(ip: str) -> Tuple[str, Optional[str]]:
        name = reverse_dns(ip)
        if not name:
            name = netbios_name(ip)
        return ip, name
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as exe:
        futs = {exe.submit(_resolve, ip): ip for ip in hosts}
        for fut in as_completed(futs):
            ip, name = fut.result()
            if name:
                names[ip] = name
    return names

def compute_diff(prev_hosts: List[Dict], curr_hosts: List[Dict]):
    """
    Compare previous JSON hosts vs current hosts by IP and open_ports set.
    Return (added_hosts, removed_hosts, port_changes list)
    """
    prev_map = {h["ip"]: set(h.get("open_ports", []) or []) for h in prev_hosts}
    curr_map = {h["ip"]: set(h.get("open_ports", []) or []) for h in curr_hosts}

    added_hosts = sorted(set(curr_map) - set(prev_map), key=lambda s: tuple(map(int, s.split("."))))
    removed_hosts = sorted(set(prev_map) - set(curr_map), key=lambda s: tuple(map(int, s.split("."))))

    port_changes = []
    for ip in sorted(set(curr_map) & set(prev_map), key=lambda s: tuple(map(int, s.split(".")))):
        before = prev_map[ip]
        after = curr_map[ip]
        opened = sorted(after - before)
        closed = sorted(before - after)
        if opened or closed:
            port_changes.append({"ip": ip, "opened": opened, "closed": closed})
    return added_hosts, removed_hosts, port_changes

# ------------- Output helpers -------------
def print_table(rows, headers):
    """
    Simple fixed-width table printer for CLI.
    """
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)] if rows else [len(h) for h in headers]
    def fmt_row(r): return "  ".join(str(val).ljust(widths[i]) for i, val in enumerate(r))
    print(fmt_row(headers))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt_row(r))

def parse_ports_arg(s: str) -> List[int]:
    out = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            p = int(part)
            if 1 <= p <= 65535:
                out.append(p)
        except ValueError:
            pass
    return sorted(set(out))

def save_json(path: str, network: ipaddress.IPv4Network, rows: List[Dict]):
    data = {
        "scanned_network": str(network),
        "timestamp": datetime.now(timezone.utc).isoformat(),  # timezone-aware (no deprecation)
        "hosts": rows,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote JSON: {path}")

def save_csv(path: str, rows: List[Dict]):
    fields = ["ip", "name", "is_self", "mac", "vendor", "open_ports", "type", "http_server", "https_server"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({
                "ip": r["ip"],
                "name": r.get("name", ""),
                "is_self": r.get("is_self", False),
                "mac": r.get("mac", ""),
                "vendor": r.get("vendor", ""),
                "open_ports": ",".join(map(str, r.get("open_ports", []))) if r.get("open_ports") else "",
                "type": r.get("type", ""),
                "http_server": r.get("banners", {}).get("http", ""),
                "https_server": r.get("banners", {}).get("https", ""),
            })
    print(f"Wrote CSV: {path}")

# ------------- Main -------------
def main():
    parser = argparse.ArgumentParser(description="Network Device Scanner (Sprint 5)")
    parser.add_argument("--mode", choices=["fast", "thorough"], default="fast", help="Scan mode preset")
    parser.add_argument("--ports", help='Override ports list, e.g. "22,80,443"')
    parser.add_argument("--timeout", type=float, default=CONNECT_TIMEOUT, help="TCP connect timeout seconds")
    parser.add_argument("--json", dest="json_path", help="Write results to JSON file")
    parser.add_argument("--csv", dest="csv_path", help="Write results to CSV file")
    parser.add_argument("--workers", type=int, default=None, help="Worker threads for host/service scan")
    parser.add_argument("--resolve", action="store_true", help="Resolve hostnames (reverse DNS / NetBIOS)")
    parser.add_argument("--skip-self", action="store_true", help="Skip scanning the local host")
    parser.add_argument("--diff", dest="diff_path", help="Compare results against a previous JSON")  # NOTE: we use args.diff_path below
    parser.add_argument("--only-open", action="store_true", help="Only show hosts with open ports on screen (still saves all)")
    args = parser.parse_args()

    ports = parse_ports_arg(args.ports) if args.ports else (FAST_PORTS if args.mode == "fast" else THOROUGH_PORTS)
    timeout = float(args.timeout)

    print("Only scan networks you own or have permission to test.\n")
    net = choose_network()
    if net.num_addresses <= 2:
        print(f"Network {net} has no usable hosts.")
        return

    print("Scanning (ping sweep)…")
    live_hosts = sweep(net, workers=args.workers)
    print(f"\nLive hosts found: {len(live_hosts)}")
    if not live_hosts:
        return

    # Identify “self” and optionally skip scanning it
    self_ip, self_mac = find_self_ip_and_mac(net)
    if args.skip_self and self_ip in live_hosts:
        live_hosts = [ip for ip in live_hosts if ip != self_ip]
        print(f"Skipping self host: {self_ip}")

    print("Reading ARP table for MAC addresses…")
    arp = get_arp_table(net)

    print(f"Running service checks on live hosts ({len(ports)} ports)…")
    svc = scan_services_for_all(live_hosts, ports=ports, timeout=timeout, workers=64)

    print("Grabbing HTTP/HTTPS banners (if any)…")
    banners_map = grab_banners(svc, timeout=min(1.5, max(0.8, timeout + 0.4)), workers=64)

    # Resolve names if requested (includes self even if skipped, purely for label)
    names_map: Dict[str, str] = {}
    if args.resolve:
        print("Resolving hostnames (reverse DNS / NetBIOS)…")
        targets_for_names = list(set(live_hosts + ([self_ip] if self_ip and not args.skip_self else [])))
        names_map = resolve_names(targets_for_names)

    # Prepare rows for screen and for files
    rows_for_screen = []
    rows_for_files: List[Dict] = []
    all_ips = live_hosts[:]
    if self_ip and not args.skip_self and self_ip not in all_ips:
        all_ips.append(self_ip)
        all_ips.sort(key=lambda s: tuple(map(int, s.split("."))))

    for ip in all_ips:
        mac = arp.get(ip, "—")
        if ip == self_ip and mac == "—" and self_mac:
            mac = self_mac  # ARP doesn’t list ourselves
        vendor = vendor_lookup(mac) if mac != "—" else "—"
        open_ports = svc.get(ip, [])
        dtype = infer_type(open_ports, vendor)

        # Banner pick: choose one “best” HTTP and HTTPS banner for CSV convenience
        bmap = banners_map.get(ip, {})
        http_desc = bmap.get(80) or bmap.get(8080) or bmap.get(8000) or bmap.get(3000) or bmap.get(5000) or ""
        https_desc = bmap.get(443) or bmap.get(8443) or bmap.get(9443) or bmap.get(10443) or ""
        name = names_map.get(ip, "")
        label = " (you)" if (ip == self_ip and not args.skip_self) else ""

        # Screen row (can be filtered by --only-open)
        rows_for_screen.append((
            ip + label,
            name or "—",
            mac,
            vendor,
            ",".join(map(str, open_ports)) if open_ports else "—",
            dtype
        ))

        # File row (always full detail)
        rows_for_files.append({
            "ip": ip,
            "name": name or "",
            "is_self": (ip == self_ip),
            "mac": mac if mac != "—" else "",
            "vendor": vendor if vendor != "—" else "",
            "open_ports": open_ports,
            "type": dtype,
            "banners": {
                "http": http_desc,
                "https": https_desc,
                "raw": bmap,  # all grabbed banners
            },
        })

    # Apply --only-open filter to screen rows (JSON/CSV remain full)
    if args.only_open:
        rows_for_screen = [r for r in rows_for_screen if r[4] != "—"]

    print()
    print_table(rows_for_screen, headers=("IP Address", "Name", "MAC Address", "Vendor", "Open Ports", "Type"))
    if args.only_open and not rows_for_screen:
        print("(No hosts with open ports matched --only-open)")

    # Save outputs if requested
    if args.json_path:
        save_json(args.json_path, net, rows_for_files)
    if args.csv_path:
        save_csv(args.csv_path, rows_for_files)

    # Diff mode (fix: use args.diff_path)
    if args.diff_path:
        try:
            with open(args.diff_path, "r", encoding="utf-8") as f:
                prev = json.load(f)
            added, removed, port_changes = compute_diff(prev.get("hosts", []), rows_for_files)
            print("\nDiff vs previous:")
            print(f"- New hosts: {len(added)}")
            for ip in added:
                print(f"  + {ip}")
            print(f"- Removed hosts: {len(removed)}")
            for ip in removed:
                print(f"  - {ip}")
            if port_changes:
                print("- Port changes:")
                for pc in port_changes:
                    opened = ",".join(map(str, pc["opened"])) if pc["opened"] else ""
                    closed = ",".join(map(str, pc["closed"])) if pc["closed"] else ""
                    print(f"  ~ {pc['ip']} opened[{opened}] closed[{closed}]")
            else:
                print("- Port changes: none")
        except Exception as e:
            print(f"Could not diff with {args.diff_path}: {e}")

    print("\nNote: Scanning your own host can show ports as 'open' locally even if blocked to the network.")
    print("Use --skip-self or verify from another device (e.g., nmap from a VM). Done.")

if __name__ == "__main__":
    main()