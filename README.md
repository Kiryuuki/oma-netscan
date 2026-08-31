# OmaNetscan

OmaNetscan is a native local network discovery, service fingerprinting, and security audit sidepanel for the Omarchy Desktop Shell. It automates ARP discovery, collapses proxy-ARP Wi-Fi repeater ghost hosts, looks up hardware manufacturers using an offline IEEE OUI table, and provides on-demand port inspection and vulnerability audits.

## Features

- Fast Network Recon: Discovers all active IP and MAC addresses across your local subnet.
- Service & OS Fingerprinting: Accurately identifies Proxmox VE cluster nodes, Dokploy container platforms, KASM workspaces, Ubuntu/Debian LXCs, DNS servers, IP cameras, and smart home appliances.
- Categorized Security Auditing: Groups hosts into Active (Verified Services), Attention (Unencrypted HTTP, open SMB/RTSP, idle clients), and Risks (Insecure Telnet, unauthenticated Docker daemon APIs, plaintext FTP).
- Explicit Category Explanations: Displays detailed rationales for every host classification and actionable remediation guidance.
- Proxy-ARP / Repeater Collapse: Groups idle downstream devices sharing a single repeater MAC address into an expandable accordion to keep the interface clean.
- Offline OUI Lookup: Resolves hardware vendors locally without external API calls or telemetry.
- On-Demand Deep Scan: Runs targeted service and OS inspection asynchronously when requested.
- Desktop Notifications: Dispatches native Omarchy notifications when new previously unseen devices connect to your network.
- Ultra-Lightweight Polling: Performs single-packet liveness checks on verified hosts to ensure zero network or device performance impact.
- Descriptor-Safe Storage: Writes local state atomically with mode 0600 under restrictive permissions.

## Installation

Install using the Omarchy plugin manager:

```bash
omaplug install kiryuuki.oma-netscan
```

### Network Capabilities Setup

Direct ARP discovery requires raw socket access. Grant capabilities to arp-scan once during installation:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(which arp-scan)
```

The plugin operates unprivileged as your regular desktop user and will never prompt for sudo at runtime.

## Keyboard Shortcuts

| Key | Action |
|---|---|
| r | Rescan local network subnet |
| 1 | Switch to All hosts tab |
| 2 | Switch to Active / Verified hosts tab |
| 3 | Switch to Attention / AP hosts tab |
| 4 | Switch to Security Risks tab |
| d | Trigger deep port and service scan on selected host |
| c | Copy selected host IP to clipboard |
| m | Copy selected host MAC address to clipboard |
| e / Enter | Expand or collapse repeater downstream devices |
| Up / Down | Navigate host list |
| Esc | Close flyout panel |

## Removal

To uninstall OmaNetscan:

```bash
omaplug remove kiryuuki.oma-netscan
```

## License

Source-Available Non-Commercial License (PolyForm-Noncommercial-1.0.0).
