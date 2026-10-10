"""
Network Monitor Pro - live view of outgoing connections from this computer.

Features
  * Live table in a simple window (or --console mode for CMD)
  * Program path + digital signature check (unsigned / risky-location programs are flagged)
  * Data volume per connection (sent / received)            [needs scapy + Npcap]
  * DNS queries log (which names are being looked up)        [needs scapy + Npcap]
  * TLS SNI / plain-HTTP host info                           [needs scapy + Npcap]
  * New-program alert (first time a program uses the network)

Setup (once)
  pip install psutil scapy
  Install Npcap from https://npcap.com  (needed for DNS / SNI / data volume).
  Without scapy/Npcap the tool still works, those columns are just empty.

Run (as Administrator for full visibility)
  python network_monitor_pro.py              # window
  python network_monitor_pro.py --console    # CMD output

Options
  --console            text mode instead of window
  --ignore NAME [...]  hide these processes (e.g. --ignore discord.exe)
  --learn SECONDS      first run only: programs seen in this time are trusted (default 60)
  --reset-known        forget the list of known programs and learn again
  --iface NAME         network interface for packet capture (default: scapy's default)
  --log FILE           console mode: also append output to a file
"""

import argparse
import csv
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import psutil

try:
    from scapy.all import sniff, DNS, IP, IPv6, TCP, UDP
    HAVE_SCAPY = True
except Exception:  # scapy missing or broken
    HAVE_SCAPY = False

IS_WIN = os.name == "nt"
WINDIR = os.environ.get("SystemRoot", r"C:\Windows").lower()
KNOWN_PATH = os.path.join(os.path.expanduser("~"), ".network_monitor_known.json")

NOISY_PROCESSES = {
    "svchost.exe", "smartscreen.exe", "msmpeng.exe", "nissrv.exe",
    "searchhost.exe", "searchapp.exe", "searchindexer.exe", "system",
    "lsass.exe", "services.exe", "musnotification.exe",
    "backgroundtaskhost.exe", "runtimebroker.exe", "sihost.exe",
    "widgets.exe", "startmenuexperiencehost.exe", "textinputhost.exe",
    "msedgewebview2.exe", "onedrive.exe", "yourphone.exe",
    "phoneexperiencehost.exe", "securityhealthservice.exe",
    "compattelrunner.exe", "dllhost.exe",
}
NOISY_HOST_PARTS = (
    "microsoft.com", "windowsupdate.com", "msftconnecttest.com", "msedge.net",
    "live.com", "office.com", "office365.com", "azure.com", "azureedge.net",
    "trafficmanager.net", "msftncsi.com", "bing.com", "akamaiedge.net",
    "akadns.net", "digicert.com", "events.data",
)
NOISY_IP_PREFIXES = ("13.107.", "204.79.197.")
RISKY_DIRS = ("\\downloads\\", "\\temp\\", "\\desktop\\", "\\users\\public\\", "\\$recycle.bin\\")
HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC")
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


# ----------------------------------------------------------------------------- helpers

def is_local(ip):
    ip = ip.split("%")[0].lower()
    if ip in ("::1", "0.0.0.0", "::") or ip.startswith("fe80") or ip.startswith(("fc", "fd")):
        return True
    if ip.startswith(("127.", "10.", "192.168.", "169.254.", "224.", "239.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except ValueError:
            return False
    return False


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def parse_sni(data):
    """Return the server name from a TLS ClientHello, or '' if not found / truncated."""
    try:
        if len(data) < 44 or data[0] != 0x16 or data[5] != 0x01:
            return ""
        pos = 9 + 2 + 32                       # handshake header, version, random
        pos += 1 + data[pos]                   # session id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")   # cipher suites
        pos += 1 + data[pos]                   # compression methods
        total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(len(data), pos + total)
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0:                  # server_name
                name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                return data[pos + 5:pos + 5 + name_len].decode("ascii", "ignore")
            pos += ext_len
    except Exception:
        pass
    return ""


def parse_http(data):
    """Return 'GET /path (Host: example.com)' for a plain HTTP request, or ''."""
    try:
        first = data.split(b"\r\n", 1)[0].decode("latin-1")
        first = " ".join(first.split(" ")[:2])[:70]
        m = re.search(rb"\r\nHost:\s*([^\r\n]+)", data, re.I)
        host = m.group(1).decode("latin-1") if m else "?"
        return f"HTTP {first} (Host: {host})"
    except Exception:
        return ""


def check_signature(path):
    """Authenticode check through PowerShell (Windows only). Returns a short label."""
    if not IS_WIN:
        return "n/a (Windows only)"
    if not path or not os.path.exists(path):
        return "unknown (no access)"
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath $env:NM_PATH; "
        "$subj = ''; if ($s.SignerCertificate) { $subj = $s.SignerCertificate.Subject }; "
        "Write-Output ($s.Status.ToString() + '|' + $subj)"
    )
    try:
        env = dict(os.environ, NM_PATH=path)
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=25, env=env,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )
        status, _, subject = res.stdout.strip().partition("|")
        m = re.search(r'CN=(?:"([^"]+)"|([^,]+))', subject)
        cn = (m.group(1) or m.group(2)).strip() if m else ""
        if status == "Valid":
            return f"Signed: {cn}" if cn else "Signed"
        if status == "NotSigned":
            return "UNSIGNED"
        return f"INVALID ({status or 'error'})"
    except Exception:
        return "unknown (check failed)"


# ----------------------------------------------------------------------------- core

class Monitor:
    def __init__(self, args):
        self.args = args
        self.lock = threading.RLock()
        self.stop_ev = threading.Event()
        self.pool = ThreadPoolExecutor(max_workers=4)

        self.conns = {}          # (pid, lport, rip, rport) -> record
        self.by_tuple = {}       # (lport, rip, rport) -> record
        self.pending_meta = {}   # SNI/HTTP seen before the poller noticed the connection
        self.tls_buf = {}        # fragmented ClientHello buffers
        self.dns = deque(maxlen=3000)
        self.dns_total = 0
        self.alerts = deque(maxlen=1000)
        self.alert_total = 0
        self.ip_names = {}       # ip -> name from DNS answers
        self.rdns_cache = {}
        self.proc_cache = {}
        self.sig_cache = {}
        self.sig_pending = set()
        self.sig_alerted = set()
        self.udp_ports = {}
        self.local_ips = set()
        self.ignored = {n.lower() for n in args.ignore}
        self.keep_closed = 45
        self.poll_error = ""
        self.sniff_status = "off"
        self.is_admin = self._admin()

        self.known = {}
        self.known_dirty = False
        first_run = True
        if not args.reset_known:
            try:
                with open(KNOWN_PATH, encoding="utf-8") as f:
                    self.known = json.load(f)
                first_run = False
            except FileNotFoundError:
                pass
            except Exception:
                self.known = {}
        self.learning_until = time.time() + args.learn if first_run else 0

    # -- misc
    @staticmethod
    def _admin():
        try:
            return bool(ctypes_windll().shell32.IsUserAnAdmin()) if IS_WIN else os.geteuid() == 0
        except Exception:
            return False

    @property
    def learning(self):
        return time.time() < self.learning_until

    @property
    def sniff_ok(self):
        return self.sniff_status == "running"

    def add_alert(self, kind, msg):
        a = {"time": time.time(), "kind": kind, "msg": msg}
        with self.lock:
            self.alerts.append(a)
            self.alert_total += 1

    def save_known(self):
        try:
            with open(KNOWN_PATH, "w", encoding="utf-8") as f:
                json.dump(self.known, f, indent=1)
            self.known_dirty = False
        except Exception:
            pass

    # -- lifecycle
    def start(self):
        threading.Thread(target=self._poll_loop, daemon=True).start()
        self._start_sniffer()

    def stop(self):
        self.stop_ev.set()
        self.save_known()
        self.pool.shutdown(wait=False, cancel_futures=True)

    def _poll_loop(self):
        last_save = time.time()
        while not self.stop_ev.is_set():
            try:
                self.poll_once()
            except Exception as e:
                self.poll_error = str(e)[:80]
            if self.known_dirty and time.time() - last_save > 10:
                self.save_known()
                last_save = time.time()
            self.stop_ev.wait(1.0)

    # -- process / signature info
    def proc_info(self, pid):
        if not pid:
            return "unknown", ""
        hit = self.proc_cache.get(pid)
        if hit and time.time() - hit[0] < 60:
            return hit[1], hit[2]
        name, path = "unknown", ""
        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                path = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                path = ""
        except Exception:
            pass
        self.proc_cache[pid] = (time.time(), name, path)
        return name, path

    def _request_signature(self, path):
        if not path or path in self.sig_cache or path in self.sig_pending:
            return
        self.sig_pending.add(path)
        self.pool.submit(self._sig_worker, path)

    def _sig_worker(self, path):
        result = check_signature(path)
        with self.lock:
            self.sig_cache[path] = result
            self.sig_pending.discard(path)
            bad = result.startswith(("UNSIGNED", "INVALID"))
            if bad and path not in self.sig_alerted and not path.lower().startswith(WINDIR) \
                    and not self.learning:
                self.sig_alerted.add(path)
                self.add_alert("UNSIGNED", f"{result}: {path}")

    def _rdns_worker(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        self.rdns_cache[ip] = name

    # -- connection polling
    def refresh_local_ips(self):
        ips = set()
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(a.address.split("%")[0])
        self.local_ips = ips

    def poll_once(self):
        now = time.time()
        self.refresh_local_ips()
        try:
            raw = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            self.poll_error = "Access denied - run as Administrator"
            return
        self.poll_error = ""
        udp, live = {}, set()
        with self.lock:
            for c in raw:
                if c.type == socket.SOCK_DGRAM:
                    if c.laddr and c.pid:
                        udp[c.laddr.port] = c.pid
                    continue
                if not c.raddr or not c.laddr or c.status not in ("ESTABLISHED", "SYN_SENT"):
                    continue
                rip, rport = c.raddr.ip, c.raddr.port
                if is_local(rip):
                    continue
                key = (c.pid or 0, c.laddr.port, rip, rport)
                live.add(key)
                rec = self.conns.get(key)
                if rec is None:
                    rec = self._new_record(key, now)
                rec["last"] = now
                rec["state"] = "open"
            self.udp_ports = udp
            for key, rec in self.conns.items():
                if key not in live and rec["state"] != "closed":
                    rec["state"], rec["closed_at"] = "closed", now
            for key in [k for k, r in self.conns.items()
                        if r["state"] == "closed" and now - r["closed_at"] > self.keep_closed]:
                rec = self.conns.pop(key)
                tup = (key[1], key[2], key[3])
                if self.by_tuple.get(tup) is rec:
                    del self.by_tuple[tup]

    def _new_record(self, key, now):
        pid, lport, rip, rport = key
        name, path = self.proc_info(pid)
        rec = {"key": key, "first": now, "last": now, "closed_at": 0, "pid": pid,
               "proc": name, "path": path, "lport": lport, "rip": rip, "rport": rport,
               "sni": "", "http": "", "sent": 0, "recv": 0, "state": "open", "new": False}
        rec.update(self.pending_meta.pop((lport, rip, rport), {}))
        self.conns[key] = rec
        self.by_tuple[(lport, rip, rport)] = rec
        if rip not in self.rdns_cache and rip not in self.ip_names:
            self.rdns_cache[rip] = ""
            self.pool.submit(self._rdns_worker, rip)
        self._request_signature(path)

        ident = (path or name).lower()
        if ident not in self.known:
            self.known[ident] = {"name": name, "first_seen": datetime.now().isoformat(timespec="seconds")}
            self.known_dirty = True
            system_noise = name.lower() in NOISY_PROCESSES and path.lower().startswith(WINDIR)
            if not self.learning and not system_noise:
                rec["new"] = True
                self.add_alert("NEW PROGRAM",
                               f"{name} (PID {pid}) connected to {rip}:{rport}  [{path or 'path unknown'}]")
        return rec

    # -- views
    def snapshot(self):
        """Copy of all connection records with computed display fields."""
        out = []
        with self.lock:
            for rec in self.conns.values():
                r = dict(rec)
                path = r["path"]
                r["sig"] = self.sig_cache.get(path, "checking..." if path else "unknown (no access)")
                host = r["sni"] or self.ip_names.get(r["rip"]) or self.rdns_cache.get(r["rip"], "")
                r["host"] = host
                r["info"] = (f"TLS SNI: {r['sni']}" if r["sni"] else r["http"])
                flags = []
                if r["new"]:
                    flags.append("NEW")
                in_win = path.lower().startswith(WINDIR) if path else False
                if r["sig"].startswith(("UNSIGNED", "INVALID")) and not in_win:
                    flags.append("UNSIGNED")
                if path and any(d in path.lower() for d in RISKY_DIRS):
                    flags.append("RISKY PATH")
                r["flags"] = ", ".join(flags)
                out.append(r)
        return out

    def is_noisy(self, r):
        if r["flags"]:
            return False
        name = r["proc"].lower()
        if name in self.ignored:
            return True
        if name in NOISY_PROCESSES or r["rip"].startswith(NOISY_IP_PREFIXES):
            return True
        host = r["host"].lower()
        return any(p in host for p in NOISY_HOST_PARTS)

    # -- packet sniffing (DNS, SNI, bytes)
    def _start_sniffer(self):
        if not HAVE_SCAPY:
            self.sniff_status = "off (pip install scapy + install Npcap)"
            return
        threading.Thread(target=self._sniff_loop, daemon=True).start()

    def _sniff_loop(self):
        try:
            self.sniff_status = "running"
            kwargs = {"iface": self.args.iface} if self.args.iface else {}
            sniff(filter="tcp or udp port 53", prn=self._on_packet, store=False,
                  stop_filter=lambda p: self.stop_ev.is_set(), **kwargs)
        except Exception as e:
            self.sniff_status = f"off ({str(e)[:70]})"

    def _on_packet(self, pkt):
        try:
            if pkt.haslayer(IP):
                ip = pkt[IP]
                src, dst, l4len = ip.src, ip.dst, (ip.len or 0) - (ip.ihl or 5) * 4
            elif pkt.haslayer(IPv6):
                ip = pkt[IPv6]
                src, dst, l4len = ip.src, ip.dst, (ip.plen or 0)
            else:
                return
            if pkt.haslayer(UDP):
                if pkt.haslayer(DNS):
                    self._on_dns(pkt, src)
                return
            if not pkt.haslayer(TCP):
                return
            tcp = pkt[TCP]
            plen = (l4len - (tcp.dataofs or 5) * 4) if l4len > 0 else len(tcp.payload)
            plen = max(0, plen)
            if src in self.local_ips:
                outgoing, tup = True, (tcp.sport, dst, tcp.dport)
            elif dst in self.local_ips:
                outgoing, tup = False, (tcp.dport, src, tcp.sport)
            else:
                return
            with self.lock:
                rec = self.by_tuple.get(tup)
                if rec is not None and plen:
                    rec["sent" if outgoing else "recv"] += plen
            if outgoing and plen > 0:
                self._inspect_payload(tup, bytes(tcp.payload)[:plen], rec)
        except Exception:
            pass

    def _inspect_payload(self, tup, data, rec):
        meta = {}
        prev = self.tls_buf.pop(tup, None)
        tries = 0
        if prev is not None:
            data, tries = prev[0] + data, prev[1]
        if data[:1] == b"\x16" and len(data) > 5 and data[5] == 0x01:
            sni = parse_sni(data)
            if sni:
                meta["sni"] = sni
            elif tries < 3 and len(data) < 16384:       # ClientHello split over several segments
                if len(self.tls_buf) > 1000:
                    self.tls_buf.clear()
                self.tls_buf[tup] = (data, tries + 1)
        elif data[:4] in HTTP_METHODS:
            http = parse_http(data)
            if http:
                meta["http"] = http
        if not meta:
            return
        with self.lock:
            if rec is not None:
                rec.update(meta)
            else:
                if len(self.pending_meta) > 500:
                    self.pending_meta.clear()
                self.pending_meta[tup] = meta

    def _on_dns(self, pkt, src):
        dns = pkt[DNS]
        q = dns.qd
        if q is None:
            return
        qname = q.qname.decode("utf-8", "ignore") if isinstance(q.qname, bytes) else str(q.qname)
        qname = qname.rstrip(".")
        if dns.qr == 0:
            if src not in self.local_ips:
                return
            pid = self.udp_ports.get(pkt[UDP].sport, 0)
            name = self.proc_info(pid)[0] if pid else "?"
            d = {"time": time.time(), "proc": name, "pid": pid,
                 "type": DNS_TYPES.get(q.qtype, str(q.qtype)), "query": qname}
            with self.lock:
                self.dns.append(d)
                self.dns_total += 1
        else:
            for i in range(dns.ancount):
                rr = dns.an[i]
                if rr.type in (1, 28):
                    ip = rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata)
                    if len(self.ip_names) > 5000:
                        self.ip_names.clear()
                    self.ip_names[ip] = qname


def ctypes_windll():
    import ctypes
    return ctypes.windll


# ----------------------------------------------------------------------------- console UI

def run_console(mon, args):
    log = open(args.log, "a", encoding="utf-8") if args.log else None

    def out(line=""):
        print(line, flush=True)
        if log:
            log.write(line + "\n")
            log.flush()

    mon.start()
    out("Network Monitor Pro - console mode (Ctrl+C to stop)")
    out(f"Admin: {'yes' if mon.is_admin else 'NO (run as Administrator for full visibility)'} | "
        f"Packet capture: {mon.sniff_status}")
    if mon.learning:
        out(f"First run: learning which programs are normal for {args.learn}s (no new-program alerts yet).")
    out("")
    out(f"{'TIME':<9} {'PROCESS':<20} {'PID':<7} {'SIGNATURE':<26} {'REMOTE':<24} HOST / INFO")
    out("-" * 120)

    printed, printed_pairs, a_shown, d_shown = set(), set(), 0, 0
    try:
        while True:
            time.sleep(0.7)
            if mon.poll_error:
                out(f"!! {mon.poll_error}")
            for r in sorted(mon.snapshot(), key=lambda x: x["first"]):
                if r["key"] in printed:
                    continue
                if r["sig"] == "checking..." and time.time() - r["first"] < 3:
                    continue
                printed.add(r["key"])
                pair = (r["proc"].lower(), r["rip"], r["rport"])
                if pair in printed_pairs or mon.is_noisy(r):
                    continue
                printed_pairs.add(pair)
                remote = f"{r['rip']}:{r['rport']}"
                extra = r["info"] or r["host"] or "-"
                flag = f"   <-- {r['flags']}" if r["flags"] else ""
                out(f"{datetime.fromtimestamp(r['first']):%H:%M:%S} {r['proc'][:19]:<20} "
                    f"{str(r['pid']):<7} {r['sig'][:25]:<26} {remote:<24} {extra}{flag}")
            with mon.lock:
                new_alerts = list(mon.alerts)[-(mon.alert_total - a_shown):] if mon.alert_total > a_shown else []
                a_shown = mon.alert_total
                new_dns = list(mon.dns)[-(mon.dns_total - d_shown):] if mon.dns_total > d_shown else []
                d_shown = mon.dns_total
            for a in new_alerts:
                out(f"{datetime.fromtimestamp(a['time']):%H:%M:%S} !! ALERT [{a['kind']}] {a['msg']}")
                print("\a", end="", flush=True)
            for d in new_dns:
                if d["proc"].lower() in mon.ignored or any(p in d["query"].lower() for p in NOISY_HOST_PARTS):
                    continue
                out(f"{datetime.fromtimestamp(d['time']):%H:%M:%S} DNS  {d['proc'][:19]:<20} "
                    f"{d['type']:<5} {d['query']}")
    except KeyboardInterrupt:
        out("\nStopped.")
    finally:
        mon.stop()
        if log:
            log.close()


# ----------------------------------------------------------------------------- window UI

def run_gui(mon):
    import tkinter as tk
    from tkinter import ttk, filedialog

    root = tk.Tk()
    root.title("Network Monitor Pro")
    root.geometry("1450x720")

    filt = tk.StringVar()
    hide_noise = tk.BooleanVar(value=True)
    only_alerts = tk.BooleanVar(value=False)
    show_closed = tk.BooleanVar(value=True)
    paused = tk.BooleanVar(value=False)
    sound = tk.BooleanVar(value=True)

    top = ttk.Frame(root, padding=6)
    top.pack(fill="x")
    ttk.Label(top, text="Filter:").pack(side="left")
    ttk.Entry(top, textvariable=filt, width=28).pack(side="left", padx=(4, 12))
    for text, var in (("Hide Windows background", hide_noise), ("Alerts only", only_alerts),
                      ("Show closed", show_closed), ("Pause", paused), ("Alert sound", sound)):
        ttk.Checkbutton(top, text=text, variable=var).pack(side="left", padx=4)

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=6)

    def make_tree(parent, columns, widths):
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings")
        for (cid, title), w in zip(columns, widths):
            tree.heading(cid, text=title)
            tree.column(cid, width=w, anchor="w", stretch=(cid in ("path", "host", "info", "msg", "query")))
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return frame, tree

    conn_cols = [("seen", "First seen"), ("proc", "Process"), ("pid", "PID"), ("sig", "Signature"),
                 ("path", "Path"), ("remote", "Remote"), ("host", "Host"), ("info", "TLS / HTTP"),
                 ("sent", "Sent"), ("recv", "Received"), ("state", "State"), ("flags", "Alert")]
    f1, tree = make_tree(nb, conn_cols, [70, 130, 55, 170, 260, 150, 200, 220, 70, 75, 55, 110])
    nb.add(f1, text="Connections")
    tree.tag_configure("new", background="#fff2a8")
    tree.tag_configure("flag", background="#ffc9c9")
    tree.tag_configure("closed", foreground="#888888")

    f2, dtree = make_tree(nb, [("time", "Time"), ("proc", "Process"), ("type", "Type"), ("query", "Queried name")],
                          [80, 160, 60, 600])
    nb.add(f2, text="DNS queries")
    f3, atree = make_tree(nb, [("time", "Time"), ("kind", "Type"), ("msg", "Details")], [80, 130, 1100])
    nb.add(f3, text="Alerts (0)")
    atree.tag_configure("alert", background="#ffe0b3")

    status = ttk.Label(root, anchor="w", padding=6)
    status.pack(fill="x")

    sort = {"col": "seen", "rev": True}
    keyfuncs = {
        "seen": lambda r: r["first"], "proc": lambda r: r["proc"].lower(), "pid": lambda r: r["pid"],
        "sig": lambda r: r["sig"], "path": lambda r: r["path"].lower(),
        "remote": lambda r: (r["rip"], r["rport"]), "host": lambda r: r["host"].lower(),
        "info": lambda r: r["info"], "sent": lambda r: r["sent"], "recv": lambda r: r["recv"],
        "state": lambda r: r["state"], "flags": lambda r: r["flags"],
    }

    def set_sort(col):
        sort["rev"] = not sort["rev"] if sort["col"] == col else False
        sort["col"] = col
        refresh_now()

    for cid, title in conn_cols:
        tree.heading(cid, text=title, command=lambda c=cid: set_sort(c))

    def visible(r):
        if only_alerts.get() and not r["flags"]:
            return False
        if hide_noise.get() and mon.is_noisy(r):
            return False
        if not show_closed.get() and r["state"] == "closed":
            return False
        t = filt.get().strip().lower()
        if t:
            hay = " ".join((r["proc"], r["path"], r["rip"], r["host"], r["info"], r["sig"], r["flags"])).lower()
            return t in hay
        return True

    def byt(r, field):
        return fmt_bytes(r[field]) if mon.sniff_ok else "n/a"

    def update_connections():
        rows = [r for r in mon.snapshot() if visible(r)]
        rows.sort(key=keyfuncs[sort["col"]], reverse=sort["rev"])
        wanted = set()
        for i, r in enumerate(rows):
            iid = "%d:%d:%s:%d" % r["key"]
            wanted.add(iid)
            values = (datetime.fromtimestamp(r["first"]).strftime("%H:%M:%S"), r["proc"], r["pid"], r["sig"],
                      r["path"], f"{r['rip']}:{r['rport']}", r["host"], r["info"],
                      byt(r, "sent"), byt(r, "recv"), r["state"], r["flags"])
            tags = []
            if r["state"] == "closed":
                tags.append("closed")
            if "UNSIGNED" in r["flags"] or "RISKY" in r["flags"]:
                tags.append("flag")
            elif r["new"]:
                tags.append("new")
            if tree.exists(iid):
                tree.item(iid, values=values, tags=tags)
            else:
                tree.insert("", "end", iid=iid, values=values, tags=tags)
            tree.move(iid, "", i)
        for iid in tree.get_children():
            if iid not in wanted:
                tree.delete(iid)

    dns_state = {"shown": 0, "sig": None}

    def update_dns():
        sig = (filt.get(), hide_noise.get())
        with mon.lock:
            total, items = mon.dns_total, list(mon.dns)
        if sig != dns_state["sig"]:
            dtree.delete(*dtree.get_children())
            dns_state["shown"] = total - len(items)
            dns_state["sig"] = sig
        new = items[-(total - dns_state["shown"]):] if total > dns_state["shown"] else []
        dns_state["shown"] = total
        t = filt.get().strip().lower()
        for d in new:
            if hide_noise.get() and (d["proc"].lower() in mon.ignored or
                                     any(p in d["query"].lower() for p in NOISY_HOST_PARTS)):
                continue
            if t and t not in (d["proc"] + " " + d["query"]).lower():
                continue
            dtree.insert("", 0, values=(datetime.fromtimestamp(d["time"]).strftime("%H:%M:%S"),
                                        d["proc"], d["type"], d["query"]))
        kids = dtree.get_children()
        for iid in kids[1500:]:
            dtree.delete(iid)

    alert_state = {"shown": 0}

    def update_alerts():
        with mon.lock:
            total, items = mon.alert_total, list(mon.alerts)
        if total <= alert_state["shown"]:
            return
        new = items[-(total - alert_state["shown"]):]
        alert_state["shown"] = total
        for a in new:
            atree.insert("", 0, values=(datetime.fromtimestamp(a["time"]).strftime("%H:%M:%S"),
                                        a["kind"], a["msg"]), tags=("alert",))
        nb.tab(f3, text=f"Alerts ({total})")
        status_alert["text"] = f"{new[-1]['kind']}: {new[-1]['msg']}"
        if sound.get():
            try:
                if IS_WIN:
                    import winsound
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                else:
                    root.bell()
            except Exception:
                pass

    status_alert = {"text": ""}

    def update_status():
        parts = [f"Admin: {'yes' if mon.is_admin else 'NO'}",
                 f"Packet capture: {mon.sniff_status}",
                 f"Connections: {len(tree.get_children())}"]
        if mon.learning:
            parts.append(f"Learning baseline ({int(mon.learning_until - time.time())}s left, no alerts yet)")
        if mon.poll_error:
            parts.append(mon.poll_error)
        if status_alert["text"]:
            parts.append("LAST ALERT -> " + status_alert["text"][:140])
        status.config(text="   |   ".join(parts))

    def refresh_now():
        update_connections()
        update_dns()
        update_alerts()
        update_status()

    def tick():
        if not paused.get():
            try:
                refresh_now()
            except tk.TclError:
                return
        root.after(1000, tick)

    # right-click menu
    menu = tk.Menu(root, tearoff=0)

    def selected_rec():
        sel = tree.selection()
        if not sel:
            return None
        with mon.lock:
            for key, rec in mon.conns.items():
                if "%d:%d:%s:%d" % key == sel[0]:
                    return dict(rec)
        return None

    def copy_ip():
        rec = selected_rec()
        if rec:
            root.clipboard_clear()
            root.clipboard_append(rec["rip"])

    def ignore_proc():
        rec = selected_rec()
        if rec:
            mon.ignored.add(rec["proc"].lower())
            refresh_now()

    def open_folder():
        rec = selected_rec()
        if rec and rec["path"] and IS_WIN:
            subprocess.Popen(["explorer", "/select,", rec["path"]])

    menu.add_command(label="Copy remote IP", command=copy_ip)
    menu.add_command(label="Hide this program", command=ignore_proc)
    menu.add_command(label="Open file location", command=open_folder)

    def popup(event):
        iid = tree.identify_row(event.y)
        if iid:
            tree.selection_set(iid)
            menu.tk_popup(event.x_root, event.y_root)

    tree.bind("<Button-3>", popup)

    # buttons
    def export_csv():
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="connections.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        fields = ["first", "proc", "pid", "sig", "path", "rip", "rport", "host", "info",
                  "sent", "recv", "state", "flags"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(fields)
            for r in sorted(mon.snapshot(), key=lambda x: x["first"]):
                row = [r[k] for k in fields]
                row[0] = datetime.fromtimestamp(r["first"]).isoformat(timespec="seconds")
                w.writerow(row)
        base = os.path.splitext(path)[0]
        with open(base + "_dns.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["time", "process", "pid", "type", "query"])
            with mon.lock:
                for d in mon.dns:
                    w.writerow([datetime.fromtimestamp(d["time"]).isoformat(timespec="seconds"),
                                d["proc"], d["pid"], d["type"], d["query"]])

    def reset_known():
        mon.known.clear()
        mon.learning_until = time.time() + mon.args.learn
        mon.save_known()

    ttk.Button(top, text="Export CSV", command=export_csv).pack(side="right", padx=4)
    ttk.Button(top, text="Re-learn known programs", command=reset_known).pack(side="right", padx=4)

    def on_close():
        mon.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    mon.start()
    tick()
    root.mainloop()


# ----------------------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description="Live network connection monitor.")
    p.add_argument("--console", action="store_true", help="text mode instead of a window")
    p.add_argument("--ignore", nargs="+", default=[], help="processes to hide")
    p.add_argument("--learn", type=int, default=60, help="first-run learning time in seconds")
    p.add_argument("--reset-known", action="store_true", help="forget known programs")
    p.add_argument("--iface", help="network interface for packet capture")
    p.add_argument("--log", help="console mode: append output to this file")
    args = p.parse_args()

    mon = Monitor(args)
    if args.console:
        run_console(mon, args)
    else:
        try:
            run_gui(mon)
        except Exception as e:
            if e.__class__.__name__ == "TclError":
                print("No display available, falling back to console mode.")
                run_console(mon, args)
            else:
                raise


if __name__ == "__main__":
    main()