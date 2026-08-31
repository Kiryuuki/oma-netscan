#!/usr/bin/env python3
"""
OmaNetscan Ultra-Lightweight Homelab Discovery, Fingerprinting & Security Audit Engine
Designed for zero-impact, ultra-lightweight network polling:
- Fast layer-2 ARP & kernel neighbour table lookups
- Targeted liveness checks for verified hosts (only 1 probe packet per known host)
- Full multi-port audit for new devices or manual rescans
- Persistent fingerprint cache & explicit category explanations
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
MAX_STATE_BYTES = 4 * 1024 * 1024  # 4 MB

# Comprehensive homelab service and exposure port list
PROBE_PORTS = [
    21,    # FTP (Insecure plaintext auth)
    22,    # SSH
    23,    # Telnet (Critical insecure plaintext)
    53,    # DNS (Pi-hole / AdGuard)
    80,    # HTTP
    139,   # NetBIOS
    443,   # HTTPS
    445,   # SMB
    554,   # RTSP Video Stream
    1883,  # MQTT Broker
    2375,  # Docker Daemon (Insecure unauthenticated API)
    3000,  # Dokploy / Gitea / Grafana
    3001,  # Uptime Kuma
    3128,  # Proxmox / Squid Proxy
    3306,  # MySQL
    3389,  # RDP Remote Desktop
    5000,  # Docker Registry / Synology DSM
    5055,  # Overseerr Media Requests
    5173,  # Vite Dev Server
    5432,  # PostgreSQL
    6379,  # Redis
    7878,  # Radarr Movie Automation
    8000,  # DVR / Hikvision Web Admin / Dev
    8006,  # Proxmox VE Web GUI
    8080,  # HTTP Alt / Proxy / Traefik
    8096,  # Jellyfin Media Server
    8123,  # Home Assistant
    8443,  # HTTPS Alt / UniFi
    8989,  # Sonarr TV Automation
    9000,  # Portainer / MinIO
    9443,  # Portainer HTTPS
    27017, # MongoDB
    37575, # Homarr Dashboard
]

PORT_NAMES = {
    21: "FTP (Plaintext)",
    22: "SSH (22)",
    23: "Telnet (Insecure)",
    53: "DNS (53)",
    80: "HTTP (80)",
    139: "NetBIOS",
    443: "HTTPS (443)",
    445: "SMB (445)",
    554: "RTSP (554)",
    1883: "MQTT (1883)",
    2375: "Docker API (2375)",
    3000: "Dokploy/App (3000)",
    3001: "Uptime Kuma (3001)",
    3128: "PVE Proxy (3128)",
    3306: "MySQL (3306)",
    3389: "RDP (3389)",
    5000: "API/DSM (5000)",
    5055: "Overseerr (5055)",
    5173: "Vite (5173)",
    5432: "Postgres (5432)",
    6379: "Redis (6379)",
    7878: "Radarr (7878)",
    8000: "Admin (8000)",
    8006: "Proxmox (8006)",
    8080: "HTTP (8080)",
    8096: "Jellyfin (8096)",
    8123: "Home Assistant (8123)",
    8443: "HTTPS (8443)",
    8989: "Sonarr (8989)",
    9000: "Portainer (9000)",
    9443: "Portainer (9443)",
    27017: "MongoDB (27017)",
    37575: "Homarr (37575)"
}


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
    
    prefix_clean = prefix.replace(":", "")
    if prefix_clean in OUI_TABLE:
        return OUI_TABLE[prefix_clean]

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


def get_local_ip_and_subnet():
    gw, iface = get_default_gateway()
    local_ip = ""
    subnet = "192.168.100.0/24"
    try:
        res = subprocess.run(["ip", "route", "show", "dev", iface], capture_output=True, text=True, timeout=2)
        for line in res.stdout.splitlines():
            if "scope link" in line and "/" in line:
                parts = line.split()
                subnet = parts[0]
                if "src" in parts:
                    local_ip = parts[parts.index("src") + 1]
    except Exception:
        pass
    if not local_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((gw, 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "192.168.100.3"
    return local_ip, subnet


def discover_mdns_devices():
    """Queries avahi-browse for mDNS friendly names, device models, and types."""
    mdns_info = {}
    try:
        res = subprocess.run(["avahi-browse", "-artp", "-t"], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("="):
                    parts = line.split(";")
                    if len(parts) >= 8:
                        ip = parts[7].strip()
                        hostname = parts[6].strip()
                        txt_records = parts[9] if len(parts) > 9 else ""
                        
                        friendly_name = ""
                        device_type = ""
                        
                        m_name = re.search(r'"name=([^"]+)"', txt_records)
                        if m_name:
                            friendly_name = m_name.group(1)
                        m_type = re.search(r'"type=([^"]+)"', txt_records)
                        if m_type:
                            device_type = m_type.group(1)

                        if not friendly_name:
                            friendly_name = hostname.replace(".local", "")

                        if ip:
                            mdns_info[ip] = {
                                "hostname": hostname,
                                "friendlyName": friendly_name,
                                "deviceType": device_type
                            }
    except Exception:
        pass
    return mdns_info


def probe_single_host(ip: str, cached_entry: dict = None):
    """
    Lightweight port probe. If cached_entry exists with known verified ports,
    first probes the known primary port to verify liveness (1 single packet).
    Only performs a full scan if liveness changes or host is unverified.
    """
    open_ports = []
    latencies = []
    ssh_banner = cached_entry.get("sshBanner", "") if cached_entry else ""

    ports_to_check = PROBE_PORTS
    # Quick liveness optimization for known verified nodes
    if cached_entry and cached_entry.get("openPorts"):
        known_p = cached_entry["openPorts"]
        # Fast single-port liveness check
        primary = known_p[0]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.35)
        t0 = time.perf_counter()
        try:
            if s.connect_ex((ip, primary)) == 0:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                s.close()
                return {
                    "openPorts": known_p,
                    "latencyMs": round(elapsed_ms, 1),
                    "hostname": cached_entry.get("hostname", ""),
                    "sshBanner": ssh_banner
                }
        except Exception:
            pass
        finally:
            s.close()

    # Full probe for new/unverified hosts
    for port in ports_to_check:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.35)
        t0 = time.perf_counter()
        try:
            res = s.connect_ex((ip, port))
            if res == 0:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                open_ports.append(port)
                latencies.append(elapsed_ms)
                if port == 22 and not ssh_banner:
                    try:
                        s.settimeout(0.5)
                        raw_b = s.recv(256).decode('latin1', errors='ignore').strip()
                        if raw_b.startswith("SSH-"):
                            ssh_banner = raw_b
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            s.close()

    open_ports.sort()
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
        "hostname": hostname,
        "sshBanner": ssh_banner
    }


def audit_host_security_and_fingerprint(ip: str, vendor: str, open_ports: list, mdns_entry: dict, local_ip: str, gateway_ip: str, ssh_banner: str = "", is_repeater: bool = False):
    """
    Evaluates role, OS, homelab apps, security vulnerabilities, category, and an explicit rationale.
    """
    warnings = []
    risk_level = "clean"
    category = "green"
    category_reason = "Verified healthy network host"

    p_set = set(open_ports)
    v_lower = vendor.lower()
    m_name = mdns_entry.get("friendlyName", "")
    m_type = mdns_entry.get("deviceType", "").lower()
    banner_lower = ssh_banner.lower()

    # --- 1. VULNERABILITY AUDIT ---
    if 23 in p_set:
        warnings.append({
            "severity": "critical",
            "port": 23,
            "title": "Telnet Exposed (Insecure Plaintext)",
            "text": "Port 23 transmits logins in plaintext. Migrate to SSH (Port 22)."
        })
        risk_level = "critical"
        category = "red"
        category_reason = "Critical Vulnerability: Unencrypted Telnet service active"

    if 2375 in p_set:
        warnings.append({
            "severity": "critical",
            "port": 2375,
            "title": "Unauthenticated Docker API Exposed",
            "text": "Port 2375 allows root container execution without auth. Enable TLS/mTLS on 2376."
        })
        risk_level = "critical"
        category = "red"
        category_reason = "Critical Vulnerability: Unprotected Docker daemon API exposed"

    if 21 in p_set:
        warnings.append({
            "severity": "warning",
            "port": 21,
            "title": "Plaintext FTP Server",
            "text": "Port 21 transmits passwords unencrypted. Migrate to SFTP (Port 22)."
        })
        if risk_level != "critical":
            risk_level = "warning"
        if category != "red":
            category = "red"
            category_reason = "Security Risk: Unencrypted FTP service active"

    if 3389 in p_set:
        warnings.append({
            "severity": "warning",
            "port": 3389,
            "title": "RDP Remote Desktop Exposed",
            "text": "Port 3389 is directly exposed to the LAN. Require VPN or KASM/Guacamole gateway."
        })
        if risk_level != "critical":
            risk_level = "warning"
        if category != "red":
            category = "orange"
            category_reason = "Attention: RDP Remote Desktop exposed on local subnet"

    if 445 in p_set or 139 in p_set:
        warnings.append({
            "severity": "info",
            "port": 445,
            "title": "SMB / NetBIOS File Sharing Active",
            "text": "Port 445 SMB active. Verify guest access is disabled and SMBv1 is disabled."
        })
        if risk_level == "clean":
            risk_level = "info"
        if category == "green":
            category = "orange"
            category_reason = "Attention: Windows/Samba file sharing active on LAN"

    if 554 in p_set:
        warnings.append({
            "severity": "info",
            "port": 554,
            "title": "RTSP Media Stream Active",
            "text": "Port 554 RTSP camera stream active. Ensure strong stream credentials."
        })
        if risk_level == "clean":
            risk_level = "info"

    if 80 in p_set and 443 not in p_set and ip != gateway_ip:
        warnings.append({
            "severity": "info",
            "port": 80,
            "title": "Unencrypted HTTP Admin Interface",
            "text": "Port 80 active without HTTPS. Session tokens are transmitted without TLS."
        })
        if category == "green" and 22 not in p_set:
            category = "orange"
            category_reason = "Attention: Web interface running over unencrypted HTTP (Port 80)"

    # --- 2. HOMELAB ROLE & OS IDENTIFICATION ---
    if ip == local_ip:
        return "This Machine (Host)", "󰌢", m_name or "Linux Workstation (yuuki)", warnings, risk_level, "green", "Active Linux Workstation (Antigravity & Omarchy Host)"

    if is_repeater:
        return "Repeater / AP Bridge", "󰀝", "Wi-Fi Client Bridge / Repeater", warnings, risk_level, "orange", "Proxy-ARP Wi-Fi repeater bridge collapsing downstream MACs"

    if ip == gateway_ip:
        return "Gateway / Router", "󰖟", f"{vendor} Gateway", warnings, risk_level, "green", "Default subnet gateway & DNS resolver"

    # Specific Proxmox VE Nodes (Ports 8006, 3128)
    if 8006 in p_set or 3128 in p_set:
        return "Proxmox VE Node", "󰒋", m_name or "Proxmox VE Node", warnings, risk_level, "green", "Proxmox VE Hypervisor Node with SSL Web GUI & cluster proxy"

    # Specific Dokploy & App Containers (e.g. .60, .9, .11, .97)
    if 3000 in p_set and (80 in p_set or 8080 in p_set or 8096 in p_set or 22 in p_set):
        return "Dokploy / Container Host", "󰒋", m_name or "Dokploy Container Host", warnings, risk_level, "green", "Dokploy PaaS & container hosting platform with web apps"

    # KASM Workspaces Host (.108)
    if ip == "192.168.100.108" or (443 in p_set and "ubuntu" in banner_lower):
        return "KASM Workspaces / App Host", "󰒋", m_name or "KASM Workspaces Host", warnings, risk_level, "green", "KASM Workspaces streaming isolated browser & desktop instances"

    # Jellyfin Media Server
    if 8096 in p_set or 8097 in p_set:
        return "Jellyfin Media Server", "󰎁", m_name or "Jellyfin Media Server", warnings, risk_level, "green", "Jellyfin Media Streaming & transcode server"

    # Uptime Kuma
    if 3001 in p_set:
        return "Uptime Kuma Monitor", "󰒋", m_name or "Uptime Kuma Monitoring", warnings, risk_level, "green", "Uptime Kuma service health & status page"

    # Media Automation
    if 5055 in p_set:
        return "Overseerr Media Manager", "󰒋", m_name or "Overseerr Media Requests", warnings, risk_level, "green", "Overseerr media discovery & automated request pipeline"
    if 7878 in p_set:
        return "Radarr Movie Automation", "󰒋", m_name or "Radarr Movie Manager", warnings, risk_level, "green", "Radarr automated movie library manager"
    if 8989 in p_set:
        return "Sonarr TV Automation", "󰒋", m_name or "Sonarr TV Manager", warnings, risk_level, "green", "Sonarr automated TV series library manager"
    if 37575 in p_set:
        return "Homarr Dashboard", "󰒋", m_name or "Homarr Homelab Dashboard", warnings, risk_level, "green", "Homarr customizable homelab service dashboard"

    # Portainer / Docker Management
    if 9000 in p_set or 9443 in p_set:
        return "Portainer Docker Host", "󰒋", m_name or "Portainer Docker Host", warnings, risk_level, "green", "Portainer container management server"

    # Home Assistant
    if 8123 in p_set or "home assistant" in v_lower:
        return "Home Assistant Hub", "󰒋", m_name or "Home Assistant Hub", warnings, risk_level, "green", "Home Assistant IoT automation & smart home hub"

    # IP Cameras
    if 554 in p_set or (8000 in p_set and 80 in p_set) or "hikvision" in v_lower or "dahua" in v_lower:
        return "IP Camera / NVR", "󰄹", m_name or f"{vendor} Security Camera", warnings, risk_level, "green", "Network security camera / video stream endpoint"

    # DNS / Pi-hole
    if 53 in p_set:
        return "DNS / Pi-hole Server", "󰒋", m_name or "DNS / Ad-Block Server", warnings, risk_level, "green", "DNS resolution & network-wide ad-blocking server"

    # SSH Banner-Based OS Detection
    if "ubuntu" in banner_lower:
        return "Ubuntu Linux Host / LXC", "󰕈", m_name or "Ubuntu Linux Host", warnings, risk_level, "green", "Ubuntu Linux node running OpenSSH daemon"

    if "debian" in banner_lower:
        return "Debian Linux Node / LXC", "󰣚", m_name or "Debian Linux LXC", warnings, risk_level, "green", "Debian Linux container/host running OpenSSH daemon"

    # Web & Development Servers
    if 3000 in p_set or 5000 in p_set or 5173 in p_set:
        return "Web App / Dev Server", "󰒋", m_name or "Web Application Server", warnings, risk_level, "green", "Custom web application / development server"
    if 22 in p_set and (80 in p_set or 443 in p_set):
        return "Linux Web Server", "󰒋", m_name or "Linux Web Server", warnings, risk_level, "green", "Linux server hosting web interfaces & remote SSH"
    if 22 in p_set:
        return "Linux Host (SSH)", "󰒋", m_name or "Linux Host (SSH)", warnings, risk_level, "green", "Linux server reachable via SSH"

    # mDNS Device Detection
    if m_type == "phone" or "galaxy" in m_name.lower() or "iphone" in m_name.lower() or "pixel" in m_name.lower() or "android" in m_name.lower():
        return "Mobile Phone", "󰄜", m_name or "Smartphone", warnings, risk_level, "green", "Mobile smartphone connected to Wi-Fi"
    if "tv" in m_name.lower() or "chromecast" in m_name.lower() or "fire" in m_name.lower():
        return "Smart TV / Media Player", "󰵪", m_name or "Smart TV", warnings, risk_level, "green", "Smart TV / streaming media player"
    if "printer" in m_name.lower() or "canon" in m_name.lower() or "epson" in m_name.lower() or "brother" in m_name.lower():
        return "Network Printer", "󰐪", m_name or "Network Printer", warnings, risk_level, "green", "Network printer active on LAN"

    if "apple" in v_lower:
        return "Apple Device", "󰀵", m_name or "Apple Device", warnings, risk_level, "green", "Apple workstation / mobile device"
    if "samsung" in v_lower or "xiaomi" in v_lower or "google" in v_lower:
        return "Mobile / Smart Device", "󰄜", m_name or f"{vendor} Device", warnings, risk_level, "green", "Smart IoT / mobile device"
    if "raspberry" in v_lower or "espressif" in v_lower or "tuya" in v_lower:
        return "IoT / Microcontroller", "󰘚", m_name or f"{vendor} IoT Appliance", warnings, risk_level, "green", "Embedded microcontroller / smart home peripheral"

    # Unfingerprinted / Idle host
    return "Generic Host", "󰖩", m_name or (vendor if vendor != "Unknown" else "Generic Device"), warnings, risk_level, ("orange" if not open_ports else "green"), ("Idle client with no common service ports listening" if not open_ports else "Generic host with active ports")


def perform_network_scan():
    """Performs full ARP, mDNS, SSH banner OS discovery, persistent cache merge, and security audits."""
    raw_devices = []
    local_ip, subnet = get_local_ip_and_subnet()
    gateway_ip, gateway_iface = get_default_gateway()
    has_cap_error = False

    prev_state = load_previous_state()
    cached_fingerprints = prev_state.get("cachedFingerprints", {})

    # 1. Layer-2 ARP Scan
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

    # 2. Augment with kernel neighbour table
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

    # Ensure Gateway & Local Host are included
    if gateway_ip and not any(d["ip"] == gateway_ip for d in raw_devices):
        raw_devices.append({"ip": gateway_ip, "mac": "", "rawVendor": ""})
    if local_ip and not any(d["ip"] == local_ip for d in raw_devices):
        raw_devices.append({"ip": local_ip, "mac": "", "rawVendor": ""})

    # Deduplicate by IP
    unique_devices = {}
    for d in raw_devices:
        unique_devices[d["ip"]] = d
    device_list = list(unique_devices.values())

    # 3. Discover mDNS Friendly Names in Parallel
    mdns_info = discover_mdns_devices()

    # 4. Multi-threaded Port & Security Probing with Liveness Short-Circuit
    probe_results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        future_map = {executor.submit(probe_single_host, d["ip"], cached_fingerprints.get(d["ip"])): d["ip"] for d in device_list}
        for future in concurrent.futures.as_completed(future_map):
            ip = future_map[future]
            try:
                res = future.result()
                prev_fp = cached_fingerprints.get(ip)
                if prev_fp:
                    if not res.get("openPorts") and prev_fp.get("openPorts"):
                        res["openPorts"] = prev_fp["openPorts"]
                    if not res.get("sshBanner") and prev_fp.get("sshBanner"):
                        res["sshBanner"] = prev_fp["sshBanner"]
                probe_results[ip] = res
            except Exception:
                prev_fp = cached_fingerprints.get(ip, {})
                probe_results[ip] = {
                    "openPorts": prev_fp.get("openPorts", []),
                    "latencyMs": None,
                    "hostname": prev_fp.get("hostname", ""),
                    "sshBanner": prev_fp.get("sshBanner", "")
                }

    # 5. Group by MAC Address & Classify
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
    total_security_warnings = 0
    green_count = 0
    orange_count = 0
    red_count = 0
    new_cached_fingerprints = {}

    for mac, items in mac_groups.items():
        is_repeater = len(items) > 2
        vendor = resolve_vendor(mac)
        if not vendor or vendor == "Unknown":
            vendor = items[0].get("rawVendor") or resolve_vendor(mac)

        if is_repeater:
            repeaters_count += 1
            idle_downstream = []
            repeater_has_red = False

            for item in sorted(items, key=lambda x: [int(p) for p in x["ip"].split(".")]):
                ip = item["ip"]
                pr = probe_results.get(ip, {})
                mdns_entry = mdns_info.get(ip, {})
                g_type, g_icon, friendly_label, warnings, risk, cat, cat_reason = audit_host_security_and_fingerprint(
                    ip, vendor, pr.get("openPorts", []), mdns_entry, local_ip, gateway_ip, pr.get("sshBanner", ""), is_repeater=False
                )

                if pr.get("openPorts") or g_type != "Generic Host":
                    new_cached_fingerprints[ip] = {
                        "openPorts": pr.get("openPorts", []),
                        "guessedType": g_type,
                        "friendlyName": friendly_label,
                        "typeIcon": g_icon,
                        "sshBanner": pr.get("sshBanner", "")
                    }

                if warnings:
                    total_security_warnings += len(warnings)
                if cat == "red":
                    red_count += 1
                    repeater_has_red = True
                elif cat == "green":
                    green_count += 1
                else:
                    orange_count += 1

                host_obj = {
                    "isRepeater": False,
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": mdns_entry.get("hostname") or pr.get("hostname", ""),
                    "friendlyName": friendly_label,
                    "openPorts": pr.get("openPorts", []),
                    "portLabels": [PORT_NAMES.get(p, str(p)) for p in pr.get("openPorts", [])],
                    "latencyMs": pr.get("latencyMs"),
                    "guessedType": g_type,
                    "typeIcon": g_icon,
                    "sshBanner": pr.get("sshBanner", ""),
                    "warnings": warnings,
                    "riskLevel": risk,
                    "category": cat,
                    "categoryReason": cat_reason,
                    "isSelf": ip == local_ip,
                    "isGateway": ip == gateway_ip
                }

                if (pr.get("openPorts") and len(pr.get("openPorts")) > 0) or g_type != "Generic Host":
                    structured_hosts.append(host_obj)
                    total_distinct_hosts += 1
                else:
                    idle_downstream.append(host_obj)
                    total_downstream_hosts += 1

            if idle_downstream:
                repeater_cat = "red" if repeater_has_red else "orange"
                structured_hosts.append({
                    "isRepeater": True,
                    "mac": mac,
                    "vendor": vendor,
                    "deviceCount": len(idle_downstream),
                    "summary": f"Behind Repeater / AP ({len(idle_downstream)} idle devices)",
                    "downstreamHosts": idle_downstream,
                    "typeIcon": "󰀝",
                    "category": repeater_cat,
                    "categoryReason": f"Proxy-ARP Wi-Fi bridge collapsing {len(idle_downstream)} idle devices under single MAC"
                })
        else:
            for item in items:
                ip = item["ip"]
                pr = probe_results.get(ip, {})
                mdns_entry = mdns_info.get(ip, {})
                g_type, g_icon, friendly_label, warnings, risk, cat, cat_reason = audit_host_security_and_fingerprint(
                    ip, vendor, pr.get("openPorts", []), mdns_entry, local_ip, gateway_ip, pr.get("sshBanner", ""), is_repeater=False
                )

                if pr.get("openPorts") or g_type != "Generic Host":
                    new_cached_fingerprints[ip] = {
                        "openPorts": pr.get("openPorts", []),
                        "guessedType": g_type,
                        "friendlyName": friendly_label,
                        "typeIcon": g_icon,
                        "sshBanner": pr.get("sshBanner", "")
                    }

                if warnings:
                    total_security_warnings += len(warnings)
                if cat == "red":
                    red_count += 1
                elif cat == "green":
                    green_count += 1
                else:
                    orange_count += 1

                structured_hosts.append({
                    "isRepeater": False,
                    "ip": ip,
                    "mac": mac if not mac.startswith("unknown-") else "",
                    "vendor": vendor,
                    "hostname": mdns_entry.get("hostname") or pr.get("hostname", ""),
                    "friendlyName": friendly_label,
                    "openPorts": pr.get("openPorts", []),
                    "portLabels": [PORT_NAMES.get(p, str(p)) for p in pr.get("openPorts", [])],
                    "latencyMs": pr.get("latencyMs"),
                    "guessedType": g_type,
                    "typeIcon": g_icon,
                    "sshBanner": pr.get("sshBanner", ""),
                    "warnings": warnings,
                    "riskLevel": risk,
                    "category": cat,
                    "categoryReason": cat_reason,
                    "isSelf": ip == local_ip,
                    "isGateway": ip == gateway_ip
                })
                total_distinct_hosts += 1

    # PRIORITY SORTING: Gateway first, This Machine second, Proxmox/Dokploy/Kasm/Ubuntu servers, then idle devices/repeaters
    def sort_key(h):
        if h.get("isGateway"):
            return (0, 0, 0, 0)
        if h.get("isSelf"):
            return (1, 0, 0, 0)
        if not h.get("isRepeater"):
            gtype = h.get("guessedType", "")
            if "Proxmox" in gtype:
                prio = 2
            elif "Dokploy" in gtype:
                prio = 3
            elif "KASM" in gtype or "Jellyfin" in gtype or "Home Assistant" in gtype:
                prio = 4
            elif "Ubuntu" in gtype:
                prio = 5
            elif "Debian" in gtype:
                prio = 6
            elif len(h.get("openPorts", [])) > 0:
                prio = 7
            else:
                prio = 8
            return (prio, *[int(p) for p in h["ip"].split(".")])
        return (9, h.get("deviceCount", 0) * -1, 0, 0)

    structured_hosts.sort(key=sort_key)
    now_ts = int(time.time())

    # 6. Diff & Notifications
    prev_macs = set(prev_state.get("knownMacs", []))
    current_macs = set(d["mac"] for d in device_list if d["mac"] and not d["mac"].startswith("unknown-"))
    new_macs = current_macs - prev_macs if prev_macs else set()

    if prev_macs and new_macs:
        for host in structured_hosts:
            if not host.get("isRepeater") and host.get("mac") in new_macs:
                send_notification(f"New Device: {host['friendlyName']} ({host['ip']})", f"Type: {host['guessedType']} · Vendor: {host['vendor']}")
            elif host.get("isRepeater") and host.get("mac") in new_macs:
                send_notification(f"New Repeater Detected ({host['mac']})", f"{host['deviceCount']} devices connected")

    doc = {
        "updatedAt": now_ts,
        "subnet": subnet,
        "localIp": local_ip,
        "gatewayIp": gateway_ip,
        "gatewayOnline": True,
        "totalHosts": len(device_list),
        "distinctHostsCount": total_distinct_hosts,
        "repeaterDevicesCount": total_downstream_hosts,
        "repeatersCount": repeaters_count,
        "securityWarningsCount": total_security_warnings,
        "greenCount": green_count,
        "orangeCount": orange_count,
        "redCount": red_count,
        "hasCapError": has_cap_error,
        "hosts": structured_hosts,
        "cachedFingerprints": new_cached_fingerprints,
        "knownMacs": list(current_macs.union(prev_macs))
    }

    write_atomic(STATE_FILE, doc)
    print(f"Scan complete: {total_distinct_hosts} distinct/promoted hosts, {repeaters_count} repeaters ({total_downstream_hosts} idle devices), Green:{green_count} Orange:{orange_count} Red:{red_count}.")
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
    """Executes single-host nmap -sV -O and returns structured JSON."""
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
