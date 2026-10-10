# Network Monitor Pro

A lightweight, real-time monitor for the **outgoing network connections** of your own computer.
See exactly which program is talking to which server, whether that program is signed,
what names it looks up, and get alerted when a program uses the network for the first time.

Written in Python. Runs as a simple window or in the console (CMD).

## Features

- **Live connection table:** process, PID, remote IP:port, host name, state
- **Program path and digital signature check:** flags unsigned programs and programs running from risky folders (Downloads, Temp, Desktop)
- **Data volume:** bytes sent and received per connection
- **DNS query log:** which program looked up which domain
- **TLS SNI / HTTP host info:** the site name of HTTPS connections and the host of plain HTTP requests
- **New-program alert:** highlight, sound and log entry when a program connects for the first time
- **Noise filter:** hides Windows/Microsoft background traffic (toggle in the UI)
- **Sorting, filtering, pause, CSV export, right-click menu**

## Requirements

- Windows 10/11 (signature check is Windows-only; the rest also works on Linux/macOS)
- Python 3.8+
- `pip install psutil scapy`
- [Npcap](https://npcap.com) (only needed for DNS, SNI and data volume)

Without scapy/Npcap the tool still works, but those columns stay empty.

## Usage

Run from a terminal opened **as Administrator** to see all processes:

```bash
python network_monitor_pro.py              # window
python network_monitor_pro.py --console    # console mode
```

| Option | Description |
|---|---|
| `--console` | Text mode instead of a window |
| `--ignore NAME [...]` | Hide these processes, e.g. `--ignore discord.exe` |
| `--learn SECONDS` | First run: programs seen in this time are treated as known (default 60) |
| `--reset-known` | Forget known programs and learn again |
| `--iface NAME` | Network interface for packet capture |
| `--log FILE` | Console mode: also append output to a file |

## How it works

- Connections are read with `psutil` once per second and matched to their process.
- Digital signatures are checked with PowerShell `Get-AuthenticodeSignature` (cached per file).
- With Npcap, `scapy` captures packets to read DNS queries, the TLS ClientHello SNI, HTTP Host headers and byte counts.
- Programs seen for the first time are stored in `~/.network_monitor_known.json`.

## Limitations

- HTTPS content is encrypted. Only the site name (SNI) is visible.
- QUIC (HTTP/3) and DNS-over-HTTPS traffic may not show SNI or DNS details.
- Many apps resolve DNS through the Windows DNS Client service, so DNS queries are often attributed to `svchost.exe`.
- The first run trusts every program that is already running. Review the Signature column yourself.

## Privacy and legal

This tool only observes traffic of the computer it runs on and sends nothing anywhere.
Use it only on devices you own or are authorized to monitor.

## License

MIT
