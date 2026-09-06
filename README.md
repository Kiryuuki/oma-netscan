# OmaNetscan

OmaNetscan is a native local network discovery, service fingerprinting, and security audit sidepanel for the Omarchy Desktop Shell. It automates subnet discovery, collapses proxy-ARP Wi-Fi repeater ghost hosts, looks up hardware manufacturers using an offline IEEE OUI table, and provides on-demand port inspection and vulnerability audits.

## Features

- Fast Network Recon: Discovers all active IP and MAC addresses across your local subnet using standard unprivileged user-space networking.
- Service & OS Fingerprinting: Accurately identifies Proxmox VE cluster nodes, Dokploy container platforms, KASM workspaces, Ubuntu/Debian LXCs, DNS servers, IP cameras, and smart home appliances.
- Categorized Security Auditing: Groups hosts into Active (Verified Services), Attention (Unencrypted HTTP, open SMB/RTSP, idle clients), and Risks (Insecure Telnet, unauthenticated Docker daemon APIs, plaintext FTP).
- Explicit Category Explanations: Displays detailed rationales for every host classification and actionable remediation guidance.
- Proxy-ARP / Repeater Collapse: Groups idle downstream devices sharing a single repeater MAC address into an expandable accordion to keep the interface clean.
- Offline OUI Lookup: Resolves hardware vendors locally without external API calls or telemetry.
- On-Demand Deep Scan: Runs targeted service and OS inspection asynchronously when requested.
- Desktop Notifications: Dispatches native Omarchy notifications when new previously unseen devices connect to your network.
- Ultra-Lightweight Polling: Performs single-packet liveness checks on verified hosts to ensure zero network or device performance impact.
- Zero Privilege Escalation: Operates completely unprivileged using user-space networking and kernel ARP tables without elevated system permissions.
- Descriptor-Safe Storage: Writes local state atomically with mode 0600 under restrictive permissions.

## Installation

Install using the Omarchy plugin manager:

```bash
omaplug install kiryuuki.oma-netscan
```

OmaNetscan operates completely unprivileged as your regular desktop user and works out-of-the-box without elevated permissions or special setup.

## Keyboard Shortcuts

| Key | Action |
|---|---|
| r | Rescan local network subnet |
| n | Choose the network range to scan |
| 1 | Switch to All hosts tab |
| 2 | Switch to Nodes tab (hypervisors, routers, DNS) |
| 3 | Switch to LXC/OS tab (containers, Ubuntu/Debian) |
| 4 | Switch to Exposed tab (hosts with web-facing ports) |
| 5 | Switch to Clients tab (workstations, phones, cameras) |
| 6 | Switch to Audits tab (hosts with security warnings) |
| d | Trigger deep port and service scan on selected host |
| c | Copy selected host IP to clipboard |
| m | Copy selected host MAC address to clipboard |
| e / Enter | Expand or collapse repeater downstream devices |
| Up / Down | Navigate host list |
| Esc | Close flyout panel |

## Choosing the range

By default OmaNetscan scans the network behind the machine's default route, so a VPN that takes over the route is scanned instead of the LAN. Press `n` or click the range line in the panel header to pick a different one: every private interface the engine can verify is offered (LAN, tunnel, mesh), each with its CIDR, interface and address. The choice is stored in the plugin's settings and a scan starts at once. Choosing Default returns to following the route. Tunnels and meshes are scanned around the machine's own /24 rather than the whole route, so a /16 mesh stays quick.

If a stored range is no longer carried by any interface, the header marks it as not detected and the engine scans the default route instead, saying so under the header.

The engine takes the same choices on the command line: `python3 scripts/netscan_engine.py --list-networks` prints the ranges it would offer, and `--scan --subnet CIDR` scans one of them.

## Settings

The bar widget keeps its settings in the shell's layout entry for the plugin:

| Key | Default | Meaning |
|---|---|---|
| refreshIntervalMin | 15 | Minutes between background scans; also set from the Auto-scan chips in the panel |
| autoRefresh | true | Whether background scans run at all |
| scanSubnet | "" | The range picked with `n`; empty follows the default route |

## Removal

To uninstall OmaNetscan:

```bash
omaplug remove kiryuuki.oma-netscan
```

## License

Source-Available Non-Commercial License (PolyForm-Noncommercial-1.0.0).
