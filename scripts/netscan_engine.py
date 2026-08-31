#!/usr/bin/env python3
"""
OmaNetscan Discovery & Fingerprinting Engine
High-performance local network scanner with Proxy-ARP repeater de-duplication,
offline OUI vendor lookups, non-intrusive heuristic fingerprinting, and descriptor-safe atomic writes.
"""

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

STATE_DIR = Path.home() / ".local" / "state" / "omarchy" / "netscan"
STATE_FILE = STATE_DIR / "devices.json"
PLUGIN_DIR = Path(__file__).resolve().parent.parent
OUI_FILE = PLUGIN_DIR / "data" / "oui.json"
MAX_STATE_BYTES = 1024 * 1024  # 1 MB

PROBE_PORTS = [80, 443, 8006, 8096, 554, 8000, 22, 53, 445, 139, 3000, 8080, 9000, 5000, 8123, 1883, 1900]


def load_oui_table():
    if OUI_FILE.exists():
        try:
            with open(OUI_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


OUI_TABLE = load_oui_table()


def write_atomic(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    raw_bytes = (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(raw_bytes) > MAX_STATE_BYTES:
        print(f"Error: Payload size {len(raw_bytes)} exceeds ceiling {MAX_STATE_BYTES}", file=sys.stderr)
        return

    handle, temp_name = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "wb") as stream:
            stream.write(raw_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        if p.exists():
            st = p.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                p.unlink(missing_ok=True)
        os.replace(temp_name, p)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


def load_previous_state():
    if not STATE_FILE.exists():
        return {}
    try:
        st = STATE_FILE.stat()
        if st.st_uid != os.getuid() or not stat.S_ISREG(st.st_mode):
            return {}
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def resolve_vendor(mac: str) -> str:
    if not mac or mac == "incomplete":
        return "Unknown"
    norm = mac.lower().strip()
    prefix = norm[:8]
    if prefix in OUI_TABLE:
        return OUI_TABLE[prefix]
    
    # Check 6-hex format without colons
    prefix_clean = prefix.replace(":", "")
    if prefix_clean in OUI_TABLE:
        return OUI_TABLE[prefix_clean]

    # Check locally administered MAC bit (2nd char is 2, 6, A, E)
    if len(norm) >= 2 and norm[1] in "26aee":
        return "Locally Administered / Virtual"

    return "Generic Device"


def get_default_gateway():
    try:
        res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=2)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+) dev (\S+)", res.stdout)
        if m:
            return m.group(1), m.group(2)
    except Exception:
        pass
    return "192.168.100.1", "wlo1"


def get_local_subnet():
    try:
        gw, iface = get_default_gateway()
        res = subprocess.run(["ip", "route", "show", "dev", iface], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines():
            if "scope link" in line and "/" in line:
                return line.split()[0]
    except Exception:
        pass
    return "192.168.100.0/24"


def probe_single_host(ip: str):
    """Probes open ports and calculates ping/TCP latency."""
    open_ports = []
    latencies = []
    
    for port in PROBE_PORTS:
        t0 = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.12)
        try:
            res = s.connect_ex((ip, port))
            if res == 0:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                open_ports.append(port)
                latencies.append(elapsed_ms)
        except Exception:
            pass
        finally:
            s.close()

    # Calculate average latency if any port responded, else fallback quick ICMP / TCP check
    avg_latency = round(min(latencies), 1) if latencies else None

    # rDNS lookup
    hostname = ""
    try:
        host_info = socket.gethostbyaddr(ip)
        if host_info and host_info[0] and host_info[0] != ip:
            hostname = host_info[0]
    except Exception:
        pass

    return {
        "openPorts": open_ports,
        "latencyMs": avg_latency,
        "hostname": hostname
    }


def guess_device_type(vendor: str, open_ports: list, ip: str, gateway_ip: str, is_repeater: bool = False):
    """Heuristic device fingerprinting."""
    if is_repeater:
        return "Repeater / AP Bridge", "󰀝"
    if ip == gateway_ip:
        return "Gateway / Router", "󰖟"
    
    p_set = set(open_ports)
    v_lower = vendor.lower()

    if 8006 in p_set:
        return "Proxmox VE Node", "󰒋"
    if 8096 in p_set or 8097 in p_set:
        return "Jellyfin Media Server", "󰎁"
    if 554 in p_set or (8000 in p_set and 80 in p_set) or "hikvision" in v_lower or "dahua" in v_lower:
        return "IP Camera", "󰄹"
    if 8123 in p_set or "home assistant" in v_lower:
        return "Home Assistant", "󰒋"
    if 445 in p_set or 139 in p_set:
        return "Samba / Windows Host", "󰍹"
    if 53 in p_set:
        return "DNS / Pi-hole Server", "󰒋"
    if 3000 in p_set or 8080 in p_set or 9000 in p_set:
        return "Container / App Host", "󰒋"
    if 22 in p_set and (80 in p_set or 443 in p_set):
        return "Linux Web Server", "󰒋"
    if 22 in p_set:
        return "Linux Host", "󰒋"
    if "apple" in v_lower:
        return "Apple Device", "󰀵"
    if "samsung" in v_lower or "xiaomi" in v_lower or "google" in v_lower:
        return "Mobile / Smart Device", "󰄜"
    if "raspberry" in v_lower or "espressif" in v_lower or "tuya" in v_lower:
        return "IoT / Microcontroller", "󰘚"

    return "Generic Host", "󰖩"


def perform_network_scan():
    """Performs fast ARP and Neighbor discovery."""
    raw_devices = []
    gateway_ip, gateway_iface = get_default_gateway()
    subnet = get_local_subnet()
    has_cap_error = False
    
    # 1. Try arp-scan
    try:
        res = subprocess.run(["arp-scan", "--localnet", "--plain", "-x"], capture_output=True, text=True, timeout=8)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].strip().lower()
                    vendor = parts[2].strip() if len(parts) > 2 else ""
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and len(mac) == 17:
                        raw_devices.append({"ip": ip, "mac": mac, "rawVendor": vendor})
        elif "Operation not permitted" in res.stderr or "Permission denied" in res.stderr:
            has_cap_error = True
    except Exception:
        has_cap_error = True

    # 2. Augment with ip neigh
    try:
        neigh_res = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=3)
        for line in neigh_res.stdout.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\S+)", line)
            if m:
                ip, mac, state = m.group(1), m.group(2).lower(), m.group(3)
                if state in ("REACHABLE", "STALE", "DELAY"):
                    if not any(d["ip"] == ip for d in raw_devices):
                        raw_devices.append({"ip": ip, "mac": mac, "rawVendor": ""})
    except Exception:
        pass

    # Ensure Gateway is included
    if gateway_ip and not any(d["ip"] == gateway_ip for d in raw_devices):
        raw_devices.append({"ip": gateway_ip, "mac": "", "rawVendor": ""})

    # Deduplicate by IP
    unique_devices = {}
    for d in raw_devices:
        unique_devices[d["ip"]] = d
    device_list = list(unique_devices.values())

    # 3. Multi-threaded Port and Fingerprint Probing
    probe_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        future_map = {executor.submit(probe_single_host, d["ip"]): d["ip"] for d in device_list}
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                probe_results[ip] = future.result()
            except Exception:
                probe_results[ip] = {"openPorts": [], "latencyMs": None, "hostname": ""}

    # 4. Proxy-ARP / Repeater De-duplication Clustering
    mac_groups = {}
    for d in device_list:
        mac = d["mac"]
        if not mac:
            mac = "unknown-" + d["ip"]
        mac_groups.setdefault(mac, []).append(d)

    structured_hosts = []
    repeaters_count = 0
    total_distinct_hosts = 0
    total_downstream_hosts = 0

    # Sort MAC groups so primary single hosts come first, then repeaters
    for mac, items in mac_groups.items():
        is_repeater = len(items) > 2
        vendor = resolve_vendor(mac)
        if not vendor or vendor == "Unknown":
            vendor = items[0].get("rawVendor") or resolve_vendor(mac)

        if is_repeater:
            repeaters_count += 1
            downstream = []
            for item in sorted(items, key=lambda x: [int(p) for p in x["ip"].split(".")]):
                ip = item["ip"]
                pr = probe_results.get(ip, {})
                g_type, g_icon = guess_device_type(vendor, pr.get("openPorts", []), ip, gateway_ip, is_repeater=False)
                downstream.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": pr.get("hostname", ""),
                    "openPorts": pr.get("openPorts", []),
                    "latencyMs": pr.get("latencyMs"),
                    "guessedType": g_type,
                    "typeIcon": g_icon,
                })
                total_downstream_hosts += 1

            structured_hosts.append({
                "isRepeater": True,
                "mac": mac,
                "vendor": vendor,
                "deviceCount": len(items),
                "summary": f"Behind Repeater / AP ({len(items)} devices)",
                "downstreamHosts": downstream,
                "typeIcon": "󰀝"
            })
        else:
            for item in items:
                ip = item["ip"]
                pr = probe_results.get(ip, {})
                g_type, g_icon = guess_device_type(vendor, pr.get("openPorts", []), ip, gateway_ip, is_repeater=False)
                structured_hosts.append({
                    "isRepeater": False,
                    "ip": ip,
                    "mac": mac if not mac.startswith("unknown-") else "",
                    "vendor": vendor,
                    "hostname": pr.get("hostname", ""),
                    "openPorts": pr.get("openPorts", []),
                    "latencyMs": pr.get("latencyMs"),
                    "guessedType": g_type,
                    "typeIcon": g_icon,
                    "isGateway": ip == gateway_ip
                })
                total_distinct_hosts += 1

    # Sort structured hosts: Gateway first, then distinct hosts sorted by IP, then repeaters
    def sort_key(h):
        if h.get("isGateway"):
            return (0, 0, 0, 0)
        if not h.get("isRepeater"):
            return (1, *[int(p) for p in h["ip"].split(".")])
        return (2, h.get("deviceCount", 0) * -1, 0, 0)

    structured_hosts.sort(key=sort_key)

    now_ts = int(time.time())
    
    # 5. Diff against previous state for new device notifications
    prev_state = load_previous_state()
    prev_macs = set(prev_state.get("knownMacs", []))
    current_macs = set(d["mac"] for d in device_list if d["mac"] and not d["mac"].startswith("unknown-"))
    new_macs = current_macs - prev_macs if prev_macs else set()

    # Emit notification if new MACs appeared and we were already initialized
    if prev_macs and new_macs:
        for host in structured_hosts:
            if not host.get("isRepeater") and host.get("mac") in new_macs:
                send_notification(f"New Device: {host['ip']}", f"Vendor: {host['vendor']} · {host['guessedType']}")
            elif host.get("isRepeater") and host.get("mac") in new_macs:
                send_notification(f"New Repeater Detected ({host['mac']})", f"{host['deviceCount']} devices connected")

    doc = {
        "updatedAt": now_ts,
        "subnet": subnet,
        "gatewayIp": gateway_ip,
        "gatewayOnline": True,
        "totalHosts": len(device_list),
        "distinctHostsCount": total_distinct_hosts,
        "repeaterDevicesCount": total_downstream_hosts,
        "repeatersCount": repeaters_count,
        "hasCapError": has_cap_error,
        "hosts": structured_hosts,
        "knownMacs": list(current_macs.union(prev_macs))
    }

    write_atomic(STATE_FILE, doc)
    print(f"Scan complete: {total_distinct_hosts} distinct hosts, {repeaters_count} repeaters ({total_downstream_hosts} devices) on {subnet}")
    return doc


def send_notification(title: str, desc: str):
    cmd = [
        "omarchy-notification-send",
        "-g", "󰖩",
        "-u", "normal",
        "--app-name", "OmaNetscan",
        title,
        desc
    ]
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def run_deep_scan(target_ip: str):
    """Executes single-host nmap -sV -O and returns JSON."""
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", target_ip):
        return {"ok": False, "error": "Invalid target IP address"}

    try:
        cmd = ["nmap", "-sV", "-O", "--top-ports", "50", target_ip]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "ok": res.returncode == 0,
            "ip": target_ip,
            "raw": res.stdout,
            "summary": "Deep scan completed successfully" if res.returncode == 0 else res.stderr
        }
    except Exception as e:
        return {"ok": False, "ip": target_ip, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="OmaNetscan Engine")
    parser.add_argument("--scan", action="store_true", help="Run full network discovery and fingerprinting")
    parser.add_argument("--deep-scan", help="Run single-host nmap deep scan on IP")
    args = parser.parse_args()

    if args.deep_scan:
        res = run_deep_scan(args.deep_scan)
        print(json.dumps(res, indent=2))
    else:
        perform_network_scan()


if __name__ == "__main__":
    main()
