#!/usr/bin/env python3
"""
Jasper - Network Probing Toolkit

A maintained Python 3 version of the original Jasper console application.
The probing and analysis features are functional. High-risk attack menu items
are intentionally defensive placeholders rather than offensive implementations.
Run with privileges when using packet capture, ARP scan, SYN scan, or traceroute:
    sudo python3 -E jasper.py
"""

from __future__ import annotations

import csv
import datetime as dt
import importlib.util
import ipaddress
import os
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

try:
    import pandas as pd
except ModuleNotFoundError:
    pd = None
import prettytable
from pyfiglet import Figlet
from termcolor import colored

try:
    from scapy.all import (
        ARP,
        DNS,
        DNSQR,
        Ether,
        IP,
        TCP,
        UDP,
        RandShort,
        conf,
        get_if_list,
        ifaces,
        interact,
        rdpcap,
        sniff,
        sr,
        sr1,
        srp,
        traceroute,
        wrpcap,
    )
except Exception as exc:  # pragma: no cover - import guard for friendly startup errors
    print("Scapy is required. Install it with: pip3 install --pre scapy[complete]")
    raise

try:
    from dialogsGUI import dialogsGUI
    from PyQt5.QtWidgets import QApplication
except Exception:
    dialogsGUI = None
    QApplication = None

try:
    from modules.pygmaps import pygmaps
except Exception:
    pygmaps = None

try:
    from scapy.layers.inet import TCPerror
except Exception:
    TCPerror = TCP

# Quiet noisy scapy runtime warnings where possible.
try:
    import logging

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
except Exception:
    pass

VERSION = "0.3"
OUTPUT_DIR = Path("output")
MODULES_DIR = Path("modules")

f = Figlet(font="standard")
conf.verb = 0

ifacelist: List[str] = []
pkt = None
ans_arpPing = []
unans_arpPing = []
tracerouteTable = ""
tracerouteList = ""
scanPortSingleTable = None
scanPortMassTable = None
vulnerabilityList: List[dict] = []
df = pd.DataFrame() if pd is not None else None


def ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)


def pause(message: str = "Press Enter To Return Back To Main Menu") -> None:
    input(colored(message, "yellow"))


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(int(port), "tcp")
    except Exception:
        return "unknown"


def ask_file_open() -> str:
    if dialogsGUI is not None:
        dialog = dialogsGUI()
        file_name, _ = dialog.openFileNameDialog()
        return file_name
    return input(colored("Enter PCAP/PCAPNG path: ", "yellow")).strip()


def ask_file_save(default_ext: str = ".pcap") -> str:
    if dialogsGUI is not None:
        dialog = dialogsGUI()
        file_name, _ = dialog.saveFileDialog()
        return file_name
    file_name = input(colored("Enter output file path: ", "yellow")).strip()
    if file_name and not Path(file_name).suffix:
        file_name += default_ext
    return file_name


def parse_ports(text: str, default: str = "1-1024") -> List[int]:
    text = (text or default).replace(" ", "")
    ports = set()
    for part in text.split(","):
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start_i, end_i = int(start), int(end)
            if start_i > end_i:
                start_i, end_i = end_i, start_i
            ports.update(range(max(1, start_i), min(65535, end_i) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_hosts(text: str) -> List[str]:
    raw = [x.strip() for x in text.replace(";", ",").split(",") if x.strip()]
    hosts: List[str] = []
    for item in raw:
        try:
            if "/" in item:
                hosts.extend(str(ip) for ip in ipaddress.ip_network(item, strict=False).hosts())
            else:
                hosts.append(item)
        except ValueError:
            hosts.append(item)
    return hosts


def advanceMode() -> None:
    interact(mydict=globals(), mybanner="== Jasper Advanced Mode ==", loglevel=2)


def arpPing(net: str = ""):
    network = net.strip() if net else input(colored("Enter network, e.g. 192.168.1.0/24: ", "yellow")).strip()
    if not network:
        print(colored("Network cannot be empty.", "red"))
        return [], []
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=2, verbose=0)
    except Exception as exc:
        print(colored(f"Unable to scan the network: {exc}", "red"))
        return [], []

    table = prettytable.PrettyTable(["INDEX", "IP ADDRESS", "MAC"])
    for idx, (_snd, rcv) in enumerate(ans):
        table.add_row([idx, rcv.psrc, rcv.hwsrc])
    print(table if len(ans) else colored("No hosts answered ARP scan.", "yellow"))
    return ans, unans


def readPCAP(file: str):
    global pkt
    if not file:
        print(colored("No file selected.", "yellow"))
        return pkt
    try:
        print("Reading.............", end="", flush=True)
        pkt = rdpcap(file)
        print("[Completed]")
        print(colored(f"Loaded {len(pkt)} packets from {file}", "green"))
    except Exception as exc:
        print(colored(f"Not able to read the file: {exc}", "red"))
    return pkt


def savePCAP(file: str, packets=None) -> None:
    packets = pkt if packets is None else packets
    if packets is None:
        print(colored("No packets loaded. Capture or read a PCAP first.", "yellow"))
        return
    if not file:
        print(colored("No destination file selected.", "yellow"))
        return
    try:
        wrpcap(file, packets)
        print(colored(f"Saved {len(packets)} packets to {file}", "green"))
    except Exception as exc:
        print(colored(f"Not able to save the file: {exc}", "red"))


def liveSniffing():
    global pkt
    listen_iface = ifacelist or conf.iface
    print(colored("Sniffing will use interface(s): ", "yellow"), listen_iface)
    count_text = input(colored("Packet count (blank = unlimited until Ctrl+C): ", "yellow")).strip()
    count = int(count_text) if count_text.isdigit() else 0
    mode = input(colored("Choose mode: s- Summary, d- Detailed, c- Cancel: ", "yellow")).strip().lower()
    if mode == "c":
        return pkt
    try:
        if mode == "d":
            pkt = sniff(iface=listen_iface, count=count, prn=lambda x: x.show(dump=False))
        else:
            pkt = sniff(iface=listen_iface, count=count, prn=lambda x: print(x.summary()))
        print(colored(f"Captured {len(pkt)} packets.", "green"))
    except KeyboardInterrupt:
        print(colored("\nSniffing stopped.", "yellow"))
    except Exception as exc:
        print(colored(f"Sniffing failed: {exc}", "red"))
    return pkt


def list_interfaces_table() -> prettytable.PrettyTable:
    table = prettytable.PrettyTable(["ID", "NAME", "IP", "MAC"])
    for name in get_if_list():
        try:
            dev = ifaces.dev_from_name(name)
            table.add_row([dev.index, dev.name, getattr(dev, "ip", ""), getattr(dev, "mac", "")])
        except Exception:
            table.add_row(["", name, "", ""])
    return table


def addInterface() -> List[str]:
    global ifacelist
    print(colored("Control one or multiple interfaces at the same time", "yellow"))
    while True:
        print(colored(f"Current interface(s): {ifacelist or [conf.iface]}", "green"))
        print(list_interfaces_table())
        inp = input(colored("Add interface ID/name, or 99 to return: ", "yellow")).strip()
        if inp == "99":
            return ifacelist
        try:
            name = ifaces.dev_from_index(int(inp)).name if inp.isdigit() else inp
            if name not in get_if_list():
                raise ValueError("interface not found")
            if name not in ifacelist:
                ifacelist.append(name)
        except Exception:
            print(colored("Interface not found", "red"))


def removeInterface() -> List[str]:
    global ifacelist
    while True:
        print(colored(f"Current interface(s): {ifacelist or [conf.iface]}", "green"))
        inp = input(colored("Remove interface ID/name, 'all', or 99 to return: ", "yellow")).strip()
        if inp == "99":
            return ifacelist
        if inp.lower() == "all":
            ifacelist = []
            continue
        try:
            name = ifaces.dev_from_index(int(inp)).name if inp.isdigit() else inp
            if name in ifacelist:
                ifacelist.remove(name)
            else:
                print(colored("Interface is not in the active list", "yellow"))
        except Exception:
            print(colored("Interface not found", "red"))


def choose_hosts_from_arp(allow_many: bool) -> List[str]:
    hosts = []
    if ans_arpPing:
        table = prettytable.PrettyTable(["INDEX", "IP ADDRESS", "MAC"])
        discovered = []
        for idx, (_snd, rcv) in enumerate(ans_arpPing):
            discovered.append(rcv.psrc)
            table.add_row([idx, rcv.psrc, rcv.hwsrc])
        table.add_row(["m", "Manual", "Manual"])
        if allow_many:
            table.add_row(["s", "Start Scanning", ""])
        print(table)
        while True:
            choice = input("$>: ").strip().lower()
            if choice == "m":
                hosts.extend(parse_hosts(input("Enter IP/domain, comma list, or CIDR: ")))
                if not allow_many:
                    break
                print(colored(f"Scan list: {hosts}", "yellow"))
            elif allow_many and choice == "s":
                break
            elif choice.isdigit() and int(choice) < len(discovered):
                host = discovered[int(choice)]
                if host not in hosts:
                    hosts.append(host)
                if not allow_many:
                    break
                print(colored(f"Scan list: {hosts}", "yellow"))
            else:
                print(colored("Wrong option", "red"))
    else:
        hosts = parse_hosts(input(colored("Enter IP/domain, comma list, or CIDR: ", "yellow")))
    return hosts


def syn_scan_host(ip: str, ports: Sequence[int], timeout: float = 1.0) -> List[Tuple[int, str]]:
    """Robust TCP open-port scan used by both legacy and smart TUI modes.

    The original build relied on raw SYN packets only. That is fragile across
    macOS/Linux permissions, VPNs, and interfaces. This maintained build uses a
    TCP connect scan by default so scanning works consistently; it still only
    reports ports that completed a TCP connection.
    """
    try:
        address = socket.gethostbyname(ip)
    except socket.gaierror:
        print(colored(f"Cannot resolve target: {ip}", "red"))
        return []

    def check(port: int) -> Optional[Tuple[int, str]]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((address, int(port))) == 0:
                    return int(port), service_name(int(port))
        except Exception:
            return None
        return None

    open_ports: List[Tuple[int, str]] = []
    workers = max(1, min(100, len(list(ports)) if not isinstance(ports, list) else len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(check, int(port)) for port in ports]
        try:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        except KeyboardInterrupt:
            print(colored("Scan interrupted.", "yellow"))
    return sorted(open_ports, key=lambda item: item[0])


def scanOpenPorts():
    hosts = choose_hosts_from_arp(allow_many=False)
    if not hosts:
        print(colored("No host selected.", "yellow"))
        return None
    host = hosts[0]
    ports = parse_ports(input(colored("Ports (example 1-1024 or 22,80,443; blank=1-1024): ", "yellow")))
    print(colored(f"Scanning {host}", "green"))
    table = prettytable.PrettyTable(["Port Number", "Port Name", "Status"])
    for port, name in syn_scan_host(host, ports):
        table.add_row([port, name, "Open"])
    print(table)
    return table


def scanOpenPortsMass():
    hosts = choose_hosts_from_arp(allow_many=True)
    if not hosts:
        print(colored("No hosts selected.", "yellow"))
        return None
    ports = parse_ports(input(colored("Ports (example 1-1024 or 22,80,443; blank=1-1024): ", "yellow")))
    table = prettytable.PrettyTable(["IP Address", "Port Number", "Port Name", "Status"])
    for host in hosts:
        print(colored(f"Scanning {host}", "green"))
        for port, name in syn_scan_host(host, ports):
            table.add_row([host, port, name, "Open"])
    print(table.get_string(sortby="IP Address"))
    return table


def ip_api_lookup(ip: str) -> List[str]:
    url = f"http://ip-api.com/csv/{ip}?fields=status,country,regionName,city,lat,lon,org,query,reverse"
    with urllib.request.urlopen(url, timeout=5) as response:
        text = response.read().decode("utf-8", "replace").strip()
    return next(csv.reader([text]))


def tcpTraceRoute(ip: str = ""):
    ipaddress = ip.strip() if ip else input(colored("Enter IP Address or domain: ", "yellow")).strip()
    if not ipaddress:
        print(colored("Target cannot be empty.", "red"))
        return "", ""
    paths = []
    try:
        ans, _uans = traceroute(ipaddress, verbose=0)
        for snd, rcv in ans:
            paths.append([snd.ttl, rcv.src, isinstance(rcv.payload, TCPerror) or rcv.haslayer(TCP)])
            if rcv.haslayer(TCP):
                break
    except Exception as exc:
        print(colored(f"Unable to execute traceroute: {exc}", "red"))
        return "", ""

    table = prettytable.PrettyTable(["TTL", "IP Address", "Status", "Country", "City", "Latitude", "Longitude", "Company"])
    rows = [["TTL", "IP Address", "Status", "Country", "City", "Latitude", "Longitude", "Company"]]
    for ttl, hop_ip, _done in paths:
        try:
            data = ip_api_lookup(hop_ip)
            status, country, _region, city, lat, lon, org, _query, _reverse = (data + [""] * 9)[:9]
            table.add_row([ttl, hop_ip, status, country, city, lat, lon, org])
            rows.append([ttl, hop_ip, status, country, city, lat, lon, org])
        except Exception:
            table.add_row([ttl, hop_ip, "unknown", "", "", "", "", ""])
            rows.append([ttl, hop_ip, "unknown", "", "", "", "", ""])
    print(table)
    return table, rows


def resolveDNS(ip: str = ""):
    target = ip.strip() if ip else input(colored("Enter domain name or IP Address: ", "yellow")).strip()
    table = prettytable.PrettyTable(["Input", "IP Address", "Reverse DNS", "Country", "City", "Latitude", "Longitude", "Company"])
    if not target:
        print(colored("Input cannot be empty.", "red"))
        return table
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception:
        resolved_ip = target
    try:
        reverse = socket.gethostbyaddr(resolved_ip)[0]
    except Exception:
        reverse = ""
    try:
        data = ip_api_lookup(resolved_ip)
        status, country, _region, city, lat, lon, org, _query, _reverse = (data + [""] * 9)[:9]
        if status != "success":
            country = city = lat = lon = org = ""
    except Exception:
        country = city = lat = lon = org = ""
    table.add_row([target, resolved_ip, reverse, country, city, lat, lon, org])
    print(table)
    return table


def ipAddressDetails(listIps: Iterable[str]):
    table = prettytable.PrettyTable(["INDEX", "IP Address", "Status", "Country", "City", "Latitude", "Longitude", "Company"])
    rows = [["TTL", "IP Address", "Status", "Country", "City", "Latitude", "Longitude", "Company"]]
    for idx, ip in enumerate(listIps):
        try:
            data = ip_api_lookup(str(ip))
            status, country, _region, city, lat, lon, org, _query, _reverse = (data + [""] * 9)[:9]
            table.add_row([idx, ip, status, country, city, lat, lon, org])
            rows.append([idx, ip, status, country, city, lat, lon, org])
        except Exception:
            table.add_row([idx, ip, "unknown", "", "", "", "", ""])
            rows.append([idx, ip, "unknown", "", "", "", "", ""])
    print(table)
    return table, rows


def geoShow(path, passive: int = 0) -> Optional[str]:
    global tracerouteTable, tracerouteList
    if not path:
        if passive == 0:
            tracerouteTable, tracerouteList = tcpTraceRoute("")
            path = tracerouteList
        if not path:
            print(colored("No traceroute path available.", "yellow"))
            return None
    ensure_output_dir()
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = str(OUTPUT_DIR / f"traceroute_{timestamp}.html")
    points: List[Tuple[float, float]] = []
    for row in path[1:]:
        try:
            lat, lon = float(row[5]), float(row[6])
            points.append((lat, lon))
        except Exception:
            continue
    if not points:
        print(colored("No geographic points were available for this path.", "yellow"))
        return None
    if pygmaps is not None:
        mymap = pygmaps(points[0][0], points[0][1], 3)
        for lat, lon in points:
            mymap.addpoint(lat, lon, "#0000FF")
        mymap.addpath(points, "#FF0000")
        mymap.draw(file_name)
    else:
        markers = "\n".join(f"<li>{lat}, {lon}</li>" for lat, lon in points)
        Path(file_name).write_text(f"<html><body><h1>Traceroute points</h1><ul>{markers}</ul></body></html>", encoding="utf-8")
    print(colored("The file generated in " + file_name, "yellow"))
    return file_name


def convertToDataframe(packets=None):
    packets = pkt if packets is None else packets
    if pd is None:
        print(colored("Pandas is required for packet dataframe analysis. Install dependencies with: python3 -m pip install -r requirements.txt", "yellow"))
        return None
    if packets is None:
        print(colored("No packet loaded. Read PCAP or sniff traffic first.", "yellow"))
        return pd.DataFrame()
    rows = []
    for packet in packets:
        if IP not in packet:
            continue
        ip_layer = packet[IP]
        transport = packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
        rows.append(
            {
                "src": ip_layer.src,
                "dst": ip_layer.dst,
                "time": float(packet.time),
                "proto": ip_layer.proto,
                "sport": getattr(transport, "sport", None),
                "dport": getattr(transport, "dport", None),
                "payload_size": len(bytes(packet.payload)),
                "summary": packet.summary(),
            }
        )
    result = pd.DataFrame(rows, columns=["src", "dst", "time", "proto", "sport", "dport", "payload_size", "summary"])
    print(colored(f"Converted {len(result)} IP packets to dataframe.", "green"))
    return result


def packetAnalysis() -> None:
    global df
    if df is None or df.empty:
        print(colored("No dataframe loaded. Use pd - Convert to DataFrame first.", "yellow"))
        return
    unique_src = list(df["src"].dropna().unique())
    table = prettytable.PrettyTable(["INDEX", "IP ADDRESS"])
    for idx, src in enumerate(unique_src):
        table.add_row([idx, src])
    print(table)
    choices = input(colored("Choose source indexes separated by commas, or blank for all: ", "yellow")).strip()
    selected = unique_src if not choices else [unique_src[int(x)] for x in choices.split(",") if x.strip().isdigit() and int(x) < len(unique_src)]
    all_unique: List[str] = []
    for src in selected:
        subset = df[df["src"] == src]
        grouped = subset.groupby("dst", dropna=True)["payload_size"].sum().sort_values(ascending=False)
        print(colored(f"\nThe IP address {src} communicated with:", "yellow"))
        print(grouped)
        other_dsts = set(df[df["src"] != src]["dst"].dropna().unique())
        unique_dsts = [x for x in subset["dst"].dropna().unique() if x not in other_dsts]
        print(colored(f"Unique destinations reached by {src}:", "yellow"))
        print("\n".join(unique_dsts) if unique_dsts else "None")
        all_unique.extend(unique_dsts)
    if all_unique:
        ipAddressDetails(sorted(set(all_unique)))


def packetConversations() -> None:
    global df
    if df is None or df.empty:
        print(colored("No dataframe loaded. Use pd - Convert to DataFrame first.", "yellow"))
        return
    while True:
        inp = input(colored("Choose: g- General Statistics, x- Analysis, e- Export CSV, c- Cancel: ", "yellow")).strip().lower()
        if inp == "g":
            print("\nTop Sending Addresses")
            print(df.groupby("src")["payload_size"].sum().sort_values(ascending=False))
            print("\nTop Receiving Addresses")
            print(df.groupby("dst")["payload_size"].sum().sort_values(ascending=False))
            print("\nTop Conversations")
            print(df.groupby(["src", "dst"])["payload_size"].agg(["count", "sum"]).sort_values("sum", ascending=False).head(25))
        elif inp == "x":
            packetAnalysis()
        elif inp == "e":
            ensure_output_dir()
            file_name = OUTPUT_DIR / f"conversations_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            df.to_csv(file_name, index=False)
            print(colored(f"Exported {file_name}", "green"))
        elif inp == "c":
            return
        else:
            print(colored("Wrong option", "red"))


def crossTwoPCAPS() -> None:
    global df
    print(colored("Choose original PCAP file", "yellow"))
    file1 = ask_file_open()
    if not file1:
        return
    pkt1 = rdpcap(file1)
    print(colored("Choose new PCAP file", "yellow"))
    file2 = ask_file_open()
    if not file2:
        return
    pkt2 = rdpcap(file2)
    df1 = convertToDataframe(pkt1)
    df2 = convertToDataframe(pkt2)
    if df1 is None or df2 is None:
        return
    old_dsts = set(df1["dst"].dropna().unique())
    df = df2[~df2["dst"].isin(old_dsts)].reset_index(drop=True)
    print(colored(f"Number of packets to destinations unique to the new PCAP: {df.shape[0]}", "yellow"))
    if not df.empty:
        packetConversations()


def packetStructure(packets=None) -> None:
    packets = pkt if packets is None else packets
    if packets is None:
        print(colored("No packet loaded. Read PCAP or sniff traffic first.", "yellow"))
        return
    while True:
        inp = input(colored("Choose: l- List Summary, d- Show Details, e- Export Structure, c- Cancel: ", "yellow")).strip().lower()
        if inp == "l":
            for idx, packet in enumerate(packets):
                print(f"[{idx}] {packet.summary()}")
        elif inp == "d":
            start = int(input(colored(f"Enter start index [0-{len(packets)-1}]: ", "yellow")) or 0)
            end = int(input(colored(f"Enter end index [0-{len(packets)-1}]: ", "yellow")) or start)
            for idx in range(max(0, start), min(len(packets), end + 1)):
                print(f"[{idx}]")
                packets[idx].show()
        elif inp == "e":
            ensure_output_dir()
            start = int(input(colored(f"Enter start index [0-{len(packets)-1}]: ", "yellow")) or 0)
            end = int(input(colored(f"Enter end index [0-{len(packets)-1}]: ", "yellow")) or start)
            file_name = OUTPUT_DIR / f"packet_structure_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with file_name.open("w", encoding="utf-8") as handle:
                for idx in range(max(0, start), min(len(packets), end + 1)):
                    handle.write(f"[{idx}] {packets[idx].summary()}\n")
                    handle.write(packets[idx].show(dump=True))
                    handle.write("\n\n")
            print(colored(f"File exported in {file_name}", "green"))
        elif inp == "c":
            return
        else:
            print(colored("Wrong option", "red"))


def vulnerabilityScanning() -> List[dict]:
    global vulnerabilityList
    if scanPortSingleTable is None and scanPortMassTable is None:
        print(colored("Run an open-port scan first. This defensive check uses the scan results.", "yellow"))
        return vulnerabilityList
    risky = {21: "FTP clear-text login", 23: "Telnet clear-text shell", 445: "SMB exposed", 3389: "RDP exposed", 5900: "VNC exposed", 6379: "Redis exposed", 9200: "Elasticsearch exposed"}
    source_table = scanPortMassTable or scanPortSingleTable
    findings: List[dict] = []
    for row in getattr(source_table, "_rows", []):
        if len(row) == 3:
            port = int(row[0])
            host = "selected host"
        else:
            host = row[0]
            port = int(row[1])
        if port in risky:
            findings.append({"host": host, "port": port, "issue": risky[port], "recommendation": "Restrict access, require encryption, and verify patch level."})
    vulnerabilityList = findings
    if not findings:
        print(colored("No high-risk default service exposures found in current scan results.", "green"))
    else:
        table = prettytable.PrettyTable(["Host", "Port", "Issue", "Recommendation"])
        for item in findings:
            table.add_row([item["host"], item["port"], item["issue"], item["recommendation"]])
        print(table)
    return vulnerabilityList


def saveVulnerabilityList() -> None:
    if not vulnerabilityList:
        print(colored("No vulnerability list exists. Run ta first.", "yellow"))
        return
    ensure_output_dir()
    file_name = OUTPUT_DIR / f"vulnerability_list_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with file_name.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["host", "port", "issue", "recommendation"])
        writer.writeheader()
        writer.writerows(vulnerabilityList)
    print(colored(f"Saved {file_name}", "green"))


def safe_unavailable(feature: str) -> None:
    print(colored(f"{feature} is intentionally not implemented in this maintained build.", "yellow"))
    print("Jasper keeps the menu item for compatibility, but offensive MiTM, spoofing, packet replay, fuzzing, and DoS automation are disabled.")


def listModules() -> None:
    MODULES_DIR.mkdir(exist_ok=True)
    table = prettytable.PrettyTable(["Module", "Path", "Status"])
    for path in sorted(MODULES_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        status = "loadable"
        try:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            if spec is None:
                status = "not loadable"
        except Exception as exc:
            status = f"error: {exc}"
        table.add_row([path.stem, str(path), status])
    print(table if table._rows else colored("No modules found.", "yellow"))


def addNewModule() -> None:
    MODULES_DIR.mkdir(exist_ok=True)
    name = input(colored("New module name: ", "yellow")).strip().replace(" ", "_")
    if not name:
        print(colored("Module name cannot be empty.", "red"))
        return
    path = MODULES_DIR / f"{name}.py"
    if path.exists():
        print(colored("Module already exists.", "yellow"))
        return
    path.write_text('''"""Jasper user module."""\n\n\ndef run(context=None):\n    print("Hello from Jasper module")\n''', encoding="utf-8")
    print(colored(f"Created {path}", "green"))


def setConfiguration() -> None:
    while True:
        print(colored("Configuration\na- Add Interface\nb- Remove Interface\nc- List Interfaces\nx- Back", "yellow"))
        inp = input("Enter code name: ").strip().lower()
        if inp == "a":
            addInterface()
        elif inp == "b":
            removeInterface()
        elif inp == "c":
            print(list_interfaces_table())
        elif inp == "x":
            return
        else:
            print(colored("Wrong option", "red"))


def typeWriter(message: str) -> None:
    for char in message:
        print(char, end="", flush=True)
        time.sleep(0.01)


def aboutJasper() -> None:
    clear()
    print(colored(f.renderText("Jasper >>>"), "red"))
    print(colored("\t\t\t\tNetwork Probing Toolkit", "white"))
    msg = "\nJasper maintained build 0.2. Built on Scapy with PCAP analysis, host discovery, port scanning, DNS resolution, traceroute mapping, and defensive reporting.\nThe application comes with no warranty. Use only on networks you own or are authorized to test.\n"
    typeWriter(msg)


def mainmenu() -> None:
    global df, pkt, ans_arpPing, unans_arpPing, tracerouteTable, tracerouteList, scanPortSingleTable, scanPortMassTable
    ensure_output_dir()
    optionsProb = ["-----PROBE--------\t", "pa- Live Sniffing\t", "pb- Read Capture File\t", "pc- Save Capture File\t", "pd- Convert to DataFrame"]
    optionsGeneral = ["-----GENERAL--------", "ga- About Jasper", "xx- Exit Jasper\t", "-----MODULES-------", "ma- List Modules", "mb- Add New Module"]
    optionsAnalysis = ["-----ANALYSIS--------\t", "aa- Resolve DNS Names\t", "ab- Geographic Trace Route", "ac- Packet structure\t", "ad- Conversations\t", "ae- Crossover Two PCAPS"]
    optionsScan = ["-----SCAN--------\t", "sa- List Hosts\t\t", "sb- Open Ports(Single)\t", "sc- Open Ports(Mass)\t", "sd- Trace Route\t\t", "\t\t\t"]
    optionsAttacks = ["-----ATTACKS--------\t", "ta- Vulnerability Scanning", "tb- ARP Poisning (MiTMA)", "tc- Fake SSL (MiTMA)", "td- Fuzzing", "te- Reply Attack", "tf- Construct & Send Packet", "tg- Deny of Service DoS", "th- Save Vulnerability List"]
    optionsConfiguration = ["-----CONFIGURATION--", "ca- Advanced Mode", "cb- Configuration", "\t\t", "\t\t", "\t\t", "\t\t", "\t\t", "\t\t"]

    while True:
        clear()
        print(colored(f.renderText("  Jasper >>>"), "red"))
        print(colored("\t\t\t\t\t\t\t\tNetwork Probing Toolkit", "white"))
        print(colored("\t\t\t\t\t\t\t\tVersion:", "white"), colored(VERSION, "green"))
        for opt1, opt2, opt3 in zip(optionsProb, optionsAnalysis, optionsGeneral):
            print(colored(opt1, "green"), "\t", colored(opt2, "green"), "\t", colored(opt3, "green"))
        print("")
        for opt1, opt2, opt3 in zip(optionsScan, optionsAttacks, optionsConfiguration):
            print(colored(opt1, "green"), "\t", colored(opt2, "yellow"), "\t", colored(opt3, "green"))

        inp = input("Enter code name: ").strip().lower()
        try:
            if inp == "pa":
                pkt = liveSniffing()
            elif inp == "pb":
                pkt = readPCAP(ask_file_open())
            elif inp == "pc":
                savePCAP(ask_file_save(), pkt)
            elif inp == "pd":
                df = convertToDataframe(pkt)
            elif inp == "ga":
                aboutJasper()
            elif inp == "ma":
                listModules()
            elif inp == "mb":
                addNewModule()
            elif inp == "sa":
                ans_arpPing, unans_arpPing = arpPing("")
            elif inp == "sb":
                scanPortSingleTable = scanOpenPorts()
            elif inp == "sc":
                scanPortMassTable = scanOpenPortsMass()
            elif inp == "sd":
                tracerouteTable, tracerouteList = tcpTraceRoute("")
            elif inp == "aa":
                resolveDNS("")
            elif inp == "ab":
                geoShow(tracerouteList, passive=0)
            elif inp == "ac":
                packetStructure(pkt)
            elif inp == "ad":
                packetConversations()
            elif inp == "ae":
                crossTwoPCAPS()
            elif inp == "ta":
                vulnerabilityScanning()
            elif inp == "th":
                saveVulnerabilityList()
            elif inp in {"tb", "tc", "td", "te", "tf", "tg"}:
                safe_unavailable(inp)
            elif inp == "ca":
                advanceMode()
            elif inp == "cb":
                setConfiguration()
            elif inp == "xx":
                print("Bye.")
                return
            else:
                print(colored("Wrong option", "red"))
        except KeyboardInterrupt:
            print(colored("\nOperation interrupted.", "yellow"))
        except Exception as exc:
            print(colored(f"Error: {exc}", "red"))
        pause()


if __name__ == "__main__":
    if "--legacy" in sys.argv:
        app = QApplication(sys.argv) if QApplication is not None else None
        mainmenu()
    else:
        try:
            from jasper_tui import JasperDashboard

            JasperDashboard(sys.modules[__name__]).run()
        except ModuleNotFoundError as exc:
            if exc.name == "rich":
                print("Rich is required for the new colored dashboard. Install dependencies with: python3 -m pip install -r requirements.txt")
                print("Falling back to the legacy menu. You can also run: python3 jasper.py --legacy")
                app = QApplication(sys.argv) if QApplication is not None else None
                mainmenu()
            else:
                raise
