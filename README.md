# OmaNetscan

OmaNetscan is a native local network discovery and device fingerprinting sidepanel for the Omarchy Desktop Shell. It automates ARP discovery, collapses proxy-ARP Wi-Fi repeater ghost hosts, looks up hardware manufacturers using an offline IEEE OUI table, and provides on-demand port inspection.

## Features

- Fast Network Recon: Discovers all active IP and MAC addresses across your local subnet.
- Proxy-ARP / Repeater Collapse: Groups downstream devices sharing a single repeater MAC address into an expandable accordion to keep the interface clean.
- Offline OUI Lookup: Resolves hardware vendors locally without external API calls or telemetry.
- Heuristic Role Fingerprinting: Identifies IP cameras, Proxmox nodes, Jellyfin servers, Linux hosts, and IoT appliances from open port signatures.
- On-Demand Deep Scan: Runs targeted service and OS inspection asynchronously when requested.
- Desktop Notifications: Dispatches native Omarchy notifications when new previously unseen devices connect to your network.
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
