#!/usr/bin/env python3
"""Results-first colored terminal dashboard for Jasper.

This module intentionally uses Rich instead of a heavy GUI stack so Jasper keeps
working over SSH and inside ordinary terminals. It wraps the existing Jasper
operations and captures their output into a large results workspace.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import os
import shlex
import socket
import time
import sys
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:
    import termios
    import tty
except Exception:  # pragma: no cover - Windows fallback
    termios = None
    tty = None

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    psutil = None


@dataclass
class Operation:
    key: str
    aliases: List[str]
    category: str
    title: str
    description: str
    runner: Callable[[], Any]
    options: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    safe_note: str = ""
    examples: List[str] = field(default_factory=list)


class JasperDashboard:
    """A compact results-first TUI around the maintained Jasper functions."""

    def __init__(self, core: Any):
        self.core = core
        self.console = Console()
        self.show_ops = True
        self.selected: Optional[Operation] = None
        self.results: List[str] = [
            "[bold green]Jasper Smart Console v0.3.10[/bold green]",
            "Type [bold cyan]ops[/bold cyan] to show operations, [bold cyan]help[/bold cyan] for commands, or select an operation number.",
        ]
        self.history: List[str] = []
        # 0 means the results workspace is pinned to the newest output.
        # Positive values scroll backward through older result lines.
        self.result_scroll = 0
        self.command_history: List[str] = []
        self.target = "unset"
        self.ports = "1-1024"
        self.scan_timeout = 1.0
        self.scan_threads = 100
        self.sniff_count = 25
        self.sniff_timeout = 15.0
        self.sniff_detailed = False
        self.side_results = "Select an operation or run a listing command.\n\nInterface lists, scan summaries, and operation-specific quick results appear here while the main workspace remains dedicated to full results."
        self.last_result = "none"
        self.capture_state = "stopped"
        self.pcap_name = "none"
        self.packet_count = 0
        self.packet_ticks = [0] * 32
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        self.last_packets: List[Any] = []
        self.last_packet_summaries: List[str] = []
        self._ensure_default_iface()
        self._last_net_sample = None
        self._last_net_sample_id = None
        self._last_net_time = time.time()
        self._net_down_rate = 0.0
        self._net_up_rate = 0.0
        if psutil is not None:
            try:
                psutil.cpu_percent(interval=None)
            except Exception:
                pass
        self.operations = self._build_operations()
        self.selected = self.operations[0]

    def _build_operations(self) -> List[Operation]:
        c = self.core
        ops = [
            Operation("1", ["pa", "sniff", "live"], "PROBE", "Live Sniffing", "Capture packets from the active interface without opening hidden prompts.", self._run_live_sniff, {"iface": "active/default", "count": "25", "timeout": "15s", "view": "summary"}, examples=["interfaces", "iface en0", "count 50", "timeout 10", "1 then run", "packets", "packet 3"]),
            Operation("2", ["pb", "read", "pcap"], "PROBE", "Read Capture File", "Load a PCAP/PCAPNG file for analysis.", self._run_read_pcap, {"file": "prompt"}, examples=["2 then run", "pcap then run", "read then run"]),
            Operation("3", ["pc", "save"], "PROBE", "Save Capture File", "Save the current capture to a PCAP file.", self._run_save_pcap, {"file": "prompt"}, examples=["3 then run", "save then run", "export current capture as pcap"]),
            Operation("4", ["pd", "dataframe", "df"], "PROBE", "Convert to DataFrame", "Convert loaded IP packets into an analysis table. Pandas is optional until this is used.", self._run_dataframe, examples=["4 then run", "df then run", "read a pcap first, then run"]),
            Operation("5", ["sa", "hosts", "arp"], "SCAN", "List Hosts", "Discover hosts on a local network with ARP.", self._run_arp, {"network": "prompt, e.g. 192.168.1.0/24"}, examples=["5 then run", "hosts then run", "network example: 192.168.1.0/24"]),
            Operation("6", ["sb", "port", "single"], "SCAN", "Open Ports - Single", "Scan one target for open TCP ports.", self._run_single_ports, {"target": "prompt/current", "ports": "prompt/current", "timeout": "1.0s"}, examples=["target 192.168.1.15", "ports 22,80,443", "6 then run"]),
            Operation("7", ["sc", "mass"], "SCAN", "Open Ports - Mass", "Scan multiple hosts or a CIDR for open TCP ports.", self._run_mass_ports, {"targets": "prompt", "ports": "prompt/current"}, examples=["ports 1-1024", "targets example: 192.168.1.10,192.168.1.11", "CIDR example: 192.168.1.0/24"]),
            Operation("8", ["sd", "trace"], "SCAN", "Trace Route", "Trace the route to a host and summarize hops.", self._run_trace, {"target": "prompt/current"}, examples=["target 8.8.8.8", "8 then run", "trace then run"]),
            Operation("9", ["aa", "dns"], "ANALYSIS", "Resolve DNS Names", "Resolve domain/IP and enrich with reverse DNS/geographic data.", self._run_dns, {"target": "prompt/current"}, examples=["target openai.com", "target 8.8.8.8", "9 then run"]),
            Operation("10", ["ab", "geo"], "ANALYSIS", "Geographic Trace Route", "Generate an HTML map from traceroute locations.", self._run_geo, examples=["run Trace Route first", "10 then run", "geo then run"]),
            Operation("11", ["ac", "structure"], "ANALYSIS", "Packet Structure", "Inspect packet summaries, details, and export structure.", self._run_structure, examples=["read a pcap first", "11 then run", "structure then run"]),
            Operation("12", ["ad", "conversations"], "ANALYSIS", "Conversations", "Show PCAP conversation statistics and exports.", self._run_conversations, examples=["read a pcap first", "12 then run", "conversations then run"]),
            Operation("13", ["ae", "compare"], "ANALYSIS", "Compare Two PCAPs", "Find destinations in a new PCAP that did not appear in an original PCAP.", self._run_compare, examples=["13 then run", "compare then run", "select original and new pcap when prompted"]),
            Operation("14", ["ta", "vuln"], "DEFENSIVE", "Vulnerability Scanning", "Defensive checks based on previous open-port scan results.", self._run_vuln, examples=["run a port scan first", "14 then run", "vuln then run"]),
            Operation("15", ["th", "save-vuln"], "DEFENSIVE", "Save Vulnerability List", "Export defensive findings to CSV.", self._run_save_vuln, examples=["run vulnerability scan first", "15 then run", "save-vuln then run"]),
            Operation("c", ["cb", "config"], "CONFIG", "Configuration", "Manage Jasper interfaces and show interface list.", self._run_config, examples=["interfaces", "iface en0", "c then run"]),
            Operation("m", ["ma", "modules"], "CONFIG", "List Modules", "List user modules found in the modules directory.", self._run_modules, examples=["m then run", "modules then run", "place .py files in modules/"]),
            Operation("n", ["mb", "new-module"], "CONFIG", "Add New Module", "Create a starter user module.", self._run_new_module, examples=["n then run", "new-module then run", "module name: custom_probe"]),
            Operation("a", ["ga", "about"], "GENERAL", "About Jasper", "Show Jasper information and usage notice.", self._run_about, examples=["a then run", "about then run", "help"]),
        ]
        return ops

    # ----- rendering -----
    def _clear(self) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def _sparkline(self, values: List[int]) -> str:
        chars = "▁▂▃▄▅▆▇█"
        if not values or max(values) <= 0:
            return "▁" * 32
        peak = max(values)
        return "".join(chars[min(7, int(v / peak * 7))] for v in values)

    def _bar(self, label: str, value: int, total: int) -> Text:
        pct = 0 if total == 0 else int(value * 100 / total)
        blocks = "█" * max(1, pct // 5) if value else ""
        text = Text()
        text.append(f"{label:<5} ", style="bold")
        palette = {"TCP": "#9ece6a", "UDP": "#7aa2f7", "ICMP": "#bb9af7", "OTHER": "#e0af68"}
        text.append(f"{blocks:<20} ", style=palette.get(label, "#7dcfff"))
        text.append(f"{pct:>3}%", style="bold #c0caf5")
        return text

    def _render_status(self) -> Columns:
        """Top status row: traffic/session on the left, CPU/memory/network on the right."""
        return Columns(
            [self._render_traffic_session(), self._render_system_monitor()],
            equal=False,
            expand=True,
        )

    def _render_traffic_session(self) -> Panel:
        iface = self._active_iface()
        total_proto = sum(self.protocol_counts.values())
        lines = [
            Text.assemble(("packets/sec ", "bold #7dcfff"), (self._sparkline(self.packet_ticks), "#7aa2f7"), (f"   capture: {self.capture_state}   pcap: {self.pcap_name}   packets: {self.packet_count}", "#c0caf5")),
            Text.assemble(("target: ", "bold #7dcfff"), (self.target, "#e0af68"), ("   iface: ", "bold #7dcfff"), (str(iface), "#e0af68"), ("   ports: ", "bold #7dcfff"), (self.ports, "#e0af68"), ("   last: ", "bold #7dcfff"), (self.last_result, "#9ece6a")),
            self._bar("TCP", self.protocol_counts["TCP"], total_proto),
            self._bar("UDP", self.protocol_counts["UDP"], total_proto),
            self._bar("ICMP", self.protocol_counts["ICMP"], total_proto),
            self._bar("OTHER", self.protocol_counts["OTHER"], total_proto),
        ]
        return Panel(Group(*lines), title="[#c0caf5]traffic / session[/#c0caf5]", border_style="#9aa5ce", box=box.SQUARE)

    def _render_system_monitor(self) -> Panel:
        if psutil is None:
            body = Text.assemble(
                ("CPU     ", "bold #7dcfff"), ("install psutil", "#e0af68"), "\n",
                ("MEM     ", "bold #bb9af7"), ("unavailable", "#e0af68"), "\n",
                ("NET     ", "bold #9ece6a"), ("python3 -m pip install psutil", "#c0caf5"),
            )
            return Panel(body, title="[#c0caf5]system[/#c0caf5]", border_style="#9aa5ce", box=box.SQUARE)

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        down, up = self._network_rates()
        cpu_bar = self._meter(cpu, "#7aa2f7")
        mem_bar = self._meter(mem.percent, "#9ece6a")
        swap_bar = self._meter(swap.percent, "#bb9af7")
        lines = [
            Text.assemble(("cpu  ", "bold #7dcfff"), (f"{cpu:5.1f}% ", "#c0caf5"), cpu_bar),
            Text.assemble(("mem  ", "bold #e0af68"), (f"{self._fmt_bytes(mem.available)} free  {mem.percent:4.1f}% ", "#e0af68"), mem_bar),
            Text.assemble(("swap ", "bold #bb9af7"), (f"{swap.percent:4.1f}% ", "#bb9af7"), swap_bar),
            Text.assemble(("net  ", "bold #9ece6a"), ("down ", "#9ece6a"), (self._fmt_rate(down), "#9ece6a"), ("   up ", "#7aa2f7"), (self._fmt_rate(up), "#7aa2f7")),
        ]
        return Panel(Group(*lines), title="[#c0caf5]cpu / memory / network[/#c0caf5]", border_style="#9aa5ce", box=box.SQUARE)

    def _meter(self, pct: float, style: str) -> Text:
        filled = max(0, min(20, int(round(pct / 5))))
        text = Text()
        text.append("▰" * filled, style=style)
        text.append("▱" * (20 - filled), style="#565f89")
        return text

    def _fmt_bytes(self, value: float) -> str:
        units = ["B", "KiB", "MiB", "GiB", "TiB"]
        size = float(value)
        for unit in units:
            if size < 1024 or unit == units[-1]:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TiB"

    def _fmt_rate(self, value: float) -> str:
        return self._fmt_bytes(value) + "/s"

    def _network_rates(self) -> tuple[float, float]:
        if psutil is None:
            return 0.0, 0.0
        now = time.time()
        iface = self._active_iface()
        pernic = psutil.net_io_counters(pernic=True)
        counters = pernic.get(iface) or psutil.net_io_counters()
        sample_id = iface if iface in pernic else "__all__"
        previous = self._last_net_sample
        if previous is None or self._last_net_sample_id != sample_id:
            self._last_net_sample = counters
            self._last_net_sample_id = sample_id
            self._last_net_time = now
            return self._net_down_rate, self._net_up_rate
        elapsed = max(0.001, now - self._last_net_time)
        self._net_down_rate = max(0.0, (counters.bytes_recv - previous.bytes_recv) / elapsed)
        self._net_up_rate = max(0.0, (counters.bytes_sent - previous.bytes_sent) / elapsed)
        self._last_net_sample = counters
        self._last_net_sample_id = sample_id
        self._last_net_time = now
        return self._net_down_rate, self._net_up_rate

    def _render_results(self) -> Panel:
        # Results are the main workspace.  When the operation drawer is hidden,
        # give nearly all available height to this panel.  The content is
        # scrollable with commands such as `up`, `down`, `pageup`, `pagedown`,
        # `top`, and `bottom`.
        max_lines = max(18, self.console.height - (13 if not self.show_ops else 22))
        lines = self._result_lines()
        total = len(lines)
        if total <= max_lines:
            self.result_scroll = 0
            visible = lines
            title = "[bold]results workspace[/bold]"
        else:
            self.result_scroll = max(0, min(self.result_scroll, total - max_lines))
            end = total - self.result_scroll
            start = max(0, end - max_lines)
            visible = lines[start:end]
            title = f"[bold]results workspace[/bold] [dim]lines {start + 1}-{end}/{total} | up/down/pageup/pagedown/top/bottom[/dim]"
        body = "\n".join(visible)
        return Panel(body or "No results yet.", title=title, border_style="#9aa5ce", box=box.SQUARE)

    def _result_lines(self) -> List[str]:
        lines: List[str] = []
        for entry in self.results:
            parts = str(entry).splitlines() or [""]
            lines.extend(parts)

        # The quick/listing panel becomes part of the main results workspace
        # only when the operation drawer is hidden. This keeps listings visible
        # in results mode while avoiding duplication when ops/detail/listing are
        # shown side-by-side in the drawer.
        if not self.show_ops and self._has_quick_result():
            lines.extend([
                "",
                "[bold #7dcfff]listing / quick results[/bold #7dcfff]",
                "[dim]Use ops to show this beside operation details, or res to keep results focused.[/dim]",
                "",
            ])
            lines.extend(str(self.side_results).splitlines())
        return lines

    def _has_quick_result(self) -> bool:
        text = (self.side_results or "").strip()
        if not text:
            return False
        placeholders = (
            "Select an operation or run a listing command.",
            "Interface lists, scan summaries",
        )
        return not any(text.startswith(marker) for marker in placeholders)

    def _render_history(self) -> Panel:
        body = "\n".join(self.history[-5:]) or "No history yet."
        return Panel(body, title="[bold]history[/bold]", border_style="#9aa5ce", height=7, box=box.SQUARE)

    def _render_ops_drawer(self) -> Panel:
        menu = Table.grid(expand=True)
        menu.add_column(ratio=1)
        menu.add_column(ratio=2)
        menu.add_column(ratio=2)
        op_table = Table(box=None, expand=True, show_header=False, padding=(0, 1))
        op_table.add_column("key", style="bold cyan", no_wrap=True)
        op_table.add_column("operation")
        last_cat = None
        for op in self.operations:
            if op.category != last_cat:
                op_table.add_row("", f"[bold yellow]{op.category}[/bold yellow]")
                last_cat = op.category
            style = "reverse bold green" if self.selected and op.key == self.selected.key else ""
            op_table.add_row(op.key, f"[{style}]{op.title}[/{style}]" if style else op.title)

        detail = self._operation_detail()
        side = self._operation_side_results()
        menu.add_row(
            Panel(op_table, title="operations", border_style="#9aa5ce"),
            Panel(detail, title="operation detail", border_style="#9aa5ce"),
            Panel(side, title="listing / quick results", border_style="#9aa5ce"),
        )
        return Panel(menu, title="[bold]operation drawer[/bold]  [cyan]ops[/cyan]/[cyan]esc[/cyan] hides this panel", border_style="#9aa5ce", box=box.ROUNDED)

    def _operation_side_results(self) -> Group:
        text = Text.from_markup(self.side_results or "No listing result yet.")
        return Group(text)

    def _operation_detail(self) -> Group:
        op = self.selected
        if op is None:
            return Group(Text("No operation selected."))

        lines: List[Any] = [
            Text(op.title, style="bold #9ece6a"),
            Text(op.description, style="#c0caf5"),
            Text(""),
        ]

        lines.append(Text("Options", style="bold #7dcfff"))
        option_rows = self._display_options(op)
        if option_rows:
            for key, value, hint in option_rows:
                lines.append(Text.assemble(
                    (f"  {key:<12}", "bold #c0caf5"),
                    (f"{value:<22}", "#e0af68"),
                    (hint, "#565f89"),
                ))
        else:
            lines.append(Text("  No required options.", style="#565f89"))

        lines.append(Text(""))
        lines.append(Text("Actions", style="bold #7dcfff"))
        action_rows = [
            ("r / run", "execute selected operation"),
            ("e / edit", "edit target, ports, interface, timeout, workers"),
            ("ops / esc", "hide this drawer and return to results"),
        ]
        if op.title == "Live Sniffing":
            action_rows.insert(1, ("interfaces", "refresh interface list in the right panel"))
            action_rows.insert(2, ("packets / packet N", "list or expand captured packets in the right panel"))
        if "Ports" in op.title or op.category == "SCAN":
            action_rows.insert(1, ("target / ports", "set scan context without opening prompts"))
        for key, desc in action_rows:
            lines.append(Text.assemble((f"  {key:<14}", "bold #c0caf5"), (desc, "#c0caf5")))

        lines.append(Text(""))
        lines.append(Text("Examples", style="bold #7dcfff"))
        examples = op.examples or [f"{op.key} then run", "ops", "help"]
        for example in examples[:6]:
            lines.append(Text.assemble(("  • ", "#565f89"), (example, "#c0caf5")))
        if op.safe_note:
            lines.append(Text(""))
            lines.append(Text(op.safe_note, style="#e0af68"))
        return Group(*lines)

    def _display_options(self, op: Operation) -> List[tuple[str, str, str]]:
        rows: List[tuple[str, str, str]] = []
        if op.key == "1":
            rows.extend([
                ("iface", str(self._active_iface()), "use: iface en0 or interfaces"),
                ("count", str(self.sniff_count), "use: count 50; 0 captures until timeout"),
                ("timeout", f"{self.sniff_timeout:.1f}s", "use: timeout 10"),
                ("view", "detailed" if self.sniff_detailed else "summary", "use: view summary or view detailed"),
            ])
        elif op.key == "c":
            rows.extend([
                ("iface", str(self._active_iface()), "use: iface en0"),
                ("interfaces", "side panel", "use: interfaces"),
            ])
        elif op.key in {"6", "7", "8", "9"}:
            rows.append(("target", self.target, "use: target <host>"))
            if op.key in {"6", "7"}:
                rows.extend([
                    ("ports", self.ports, "use: ports 22,80,443 or 1-1024"),
                    ("timeout", f"{self.scan_timeout:.1f}s", "use: timeout 1.0"),
                    ("workers", str(self.scan_threads), "use: threads 100"),
                ])
        elif op.key == "5":
            rows.append(("network", "prompt", "example: 192.168.1.0/24"))
        elif op.options:
            for key, value in op.options.items():
                display = str(value)
                hint = ""
                if key in {"target", "targets"}:
                    display = self.target
                    hint = "use: target <host>"
                elif key == "ports":
                    display = self.ports
                    hint = "use: ports <range>"
                elif key == "timeout":
                    display = f"{self.scan_timeout:.1f}s"
                    hint = "use: timeout <seconds>"
                elif key == "threads":
                    display = str(self.scan_threads)
                    hint = "use: threads <count>"
                rows.append((key, display, hint))
        return rows

    def render(self, command_buffer: str = "") -> None:
        self._clear()
        title = Text.assemble(
            (f" {socket.gethostname()} ", "bold cyan"),
            ("Jasper Network Toolkit v0.3.10", "bold #c0caf5"),
            ("   results-first smart console", "#9ece6a"),
        )
        self.console.print(Panel(Align.left(title), border_style="#9aa5ce", box=box.SQUARE))
        self.console.print(self._render_status())
        self.console.print(self._render_results())
        if self.show_ops:
            self.console.print(self._render_ops_drawer())
        self.console.print(self._render_history())
        self.console.print(Text.assemble((" command: ", "bold #7dcfff"), (command_buffer, "#c0caf5"), ("█", "#c0caf5")))

    # ----- commands -----
    def run(self) -> None:
        """Main loop with a live-refreshing command line.

        The previous implementation used Console.input(), which blocks the entire
        process and prevents CPU/memory/network panels from refreshing until the
        user presses Enter.  This loop keeps the terminal in cbreak mode, polls
        stdin, and re-renders the dashboard every second while the user is idle.
        """
        while True:
            try:
                raw = self._read_command_dynamic()
            except (EOFError, KeyboardInterrupt):
                self.console.print("\n[green]Bye.[/green]")
                return
            raw = raw.strip()
            if not raw:
                continue
            self.command_history.append(raw)
            if not self.handle_command(raw):
                return

    def _read_command_dynamic(self) -> str:
        if os.name == "nt" or termios is None or tty is None or not sys.stdin.isatty():
            self.render()
            return self.console.input("[bold cyan] command:[/bold cyan] ")

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        buffer = ""
        last_refresh = 0.0
        try:
            tty.setcbreak(fd)
            while True:
                now = time.time()
                if now - last_refresh >= 1.0:
                    self._refresh_live_stats()
                    self.render(buffer)
                    last_refresh = now
                ready, _, _ = select.select([sys.stdin], [], [], 0.15)
                if not ready:
                    continue
                ch = sys.stdin.read(1)
                if ch in {"\r", "\n"}:
                    return buffer
                if ch == "\x03":
                    raise KeyboardInterrupt
                if ch == "\x04":
                    raise EOFError
                if ch in {"\x7f", "\b"}:
                    buffer = buffer[:-1]
                    self.render(buffer)
                    last_refresh = time.time()
                    continue
                if ch == "\x1b":
                    # Bare Escape hides the drawer. Arrow keys scroll the results
                    # workspace when no command text is being typed.
                    ready2, _, _ = select.select([sys.stdin], [], [], 0.02)
                    if ready2:
                        lead = sys.stdin.read(1)
                        ready3, _, _ = select.select([sys.stdin], [], [], 0.02)
                        tail = sys.stdin.read(1) if ready3 else ""
                        if not buffer and lead == "[" and tail == "A":
                            return "up"
                        if not buffer and lead == "[" and tail == "B":
                            return "down"
                        continue
                    return "esc"
                if ch.isprintable():
                    buffer += ch
                    self.render(buffer)
                    last_refresh = time.time()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def handle_command(self, raw: str) -> bool:
        cmd = raw.strip()
        low = cmd.lower()
        if low in {"q", "quit", "exit", "xx"}:
            self._log("session ended")
            return False
        if low in {"ops", "menu", "tab"}:
            self.show_ops = not self.show_ops
            self._log("operation drawer " + ("shown" if self.show_ops else "hidden"))
            return True
        if low in {"esc", "close", "hide", "res", "result", "results"}:
            self.show_ops = False
            if low in {"res", "result", "results"}:
                self.result_scroll = 0
                self._log("returned to results workspace")
            return True
        if low in {"interfaces", "ifaces", "list interfaces"}:
            self._show_interfaces()
            return True
        if low in {"packets", "list packets", "recent packets"}:
            self._show_packet_list()
            return True
        if low.startswith("packet ") or low.startswith("pkt "):
            self._show_packet_detail(cmd)
            return True
        if low in {"help", "?"}:
            self._help()
            return True
        if low in {"r", "run"}:
            self.run_selected()
            return True
        if low in {"e", "edit"}:
            self._edit_context()
            return True
        if low == "clear":
            self.results = []
            self.result_scroll = 0
            self._log("results cleared")
            return True
        if low in {"up", "scroll up", "k"}:
            self._scroll_results(3)
            return True
        if low in {"down", "scroll down", "j"}:
            self._scroll_results(-3)
            return True
        if low in {"pageup", "pgup", "scroll page up"}:
            self._scroll_results(max(10, self.console.height // 2))
            return True
        if low in {"pagedown", "pgdn", "scroll page down"}:
            self._scroll_results(-max(10, self.console.height // 2))
            return True
        if low in {"top", "home"}:
            self._scroll_results(10**9)
            return True
        if low in {"bottom", "end"}:
            self.result_scroll = 0
            self._log("results scrolled to bottom")
            return True
        if low == "history clear":
            self.history = []
            return True
        if low.startswith("target ") or low.startswith("set target "):
            self.target = cmd.split(None, 2)[-1] if low.startswith("set ") else cmd.split(None, 1)[1]
            self._log(f"target set to {self.target}")
            return True
        if low.startswith("ports ") or low.startswith("set ports "):
            proposed = cmd.split(None, 2)[-1] if low.startswith("set ") else cmd.split(None, 1)[1]
            try:
                parsed = self._parse_ports_safe(proposed)
                self.ports = proposed
                self._log(f"ports set to {self.ports} ({len(parsed)} ports)")
            except ValueError as exc:
                self._result(f"[red]Invalid port range: {exc}[/red]")
            return True
        if low.startswith("timeout ") or low.startswith("set timeout "):
            proposed = cmd.split(None, 2)[-1] if low.startswith("set ") else cmd.split(None, 1)[1]
            try:
                value = float(proposed)
                if value <= 0 or value > 30:
                    raise ValueError("timeout must be between 0.1 and 30 seconds")
                self.scan_timeout = value
                self.sniff_timeout = value
                self._log(f"timeout set to {value:.1f}s for scans and live sniffing")
            except ValueError as exc:
                self._result(f"[red]Invalid timeout: {exc}[/red]")
            return True
        if low.startswith("count ") or low.startswith("sniff count ") or low.startswith("set count "):
            proposed = cmd.split(None, 2)[-1] if low.startswith("set ") or low.startswith("sniff ") else cmd.split(None, 1)[1]
            try:
                value = int(proposed)
                if value < 0 or value > 100000:
                    raise ValueError("count must be between 0 and 100000; use 0 for timeout-only capture")
                self.sniff_count = value
                self._log(f"live sniff packet count set to {self.sniff_count or 'timeout-only'}")
            except ValueError as exc:
                self._result(f"[red]Invalid packet count: {exc}[/red]")
            return True
        if low.startswith("view ") or low.startswith("mode "):
            mode = cmd.split(None, 1)[1].strip().lower()
            if mode in {"summary", "s"}:
                self.sniff_detailed = False
                self._log("live sniff view mode set to summary")
            elif mode in {"detail", "d", "detailed"}:
                self.sniff_detailed = True
                self._log("live sniff view mode set to detailed")
            else:
                self._result("[red]Invalid view mode. Use: view summary or view detailed[/red]")
            return True
        if low.startswith("threads ") or low.startswith("set threads "):
            proposed = cmd.split(None, 2)[-1] if low.startswith("set ") else cmd.split(None, 1)[1]
            try:
                value = int(proposed)
                if value < 1 or value > 1000:
                    raise ValueError("threads must be between 1 and 1000")
                self.scan_threads = value
                self._log(f"scan workers set to {self.scan_threads}")
            except ValueError as exc:
                self._result(f"[red]Invalid thread count: {exc}[/red]")
            return True
        if low.startswith("iface ") or low.startswith("set iface "):
            iface = cmd.split(None, 2)[-1] if low.startswith("set ") else cmd.split(None, 1)[1]
            self.core.ifacelist = [iface]
            self._log(f"interface set to {iface}")
            return True
        op = self.find_operation(low)
        if op:
            self.selected = op
            self.show_ops = True
            self._log(f"selected {op.title}")
            return True
        self._log(f"unknown command: {cmd}. Type help.")
        return True

    def find_operation(self, token: str) -> Optional[Operation]:
        for op in self.operations:
            if token == op.key or token in op.aliases:
                return op
        return None

    def run_selected(self) -> None:
        if not self.selected:
            self._result("[yellow]No operation selected.[/yellow]")
            return
        op = self.selected
        self._log(f"running {op.title}")
        started = dt.datetime.now()
        buffer = io.StringIO()
        try:
            # Capture printed output from the legacy functions into the results workspace.
            with contextlib.redirect_stdout(buffer):
                result = op.runner()
            printed = buffer.getvalue().strip()
            if printed:
                self._result(f"[bold green]{op.title}[/bold green]\n{printed}")
            else:
                self._result(f"[bold green]{op.title} completed.[/bold green]")
            self._refresh_packet_stats()
            self.show_ops = False
            self.result_scroll = 0
            elapsed = (dt.datetime.now() - started).total_seconds()
            self.last_result = f"{op.title} ok"
            self._log(f"{op.title} completed in {elapsed:.1f}s")
        except KeyboardInterrupt:
            self._result(f"[yellow]{op.title} interrupted.[/yellow]")
            self.show_ops = False
            self.last_result = "interrupted"
        except Exception as exc:
            printed = buffer.getvalue().strip()
            if printed:
                self._result(printed)
            self._result(f"[red]Error while running {op.title}: {exc}[/red]")
            self.show_ops = False
            self.result_scroll = 0
            self.last_result = "error"
            self._log(f"error: {op.title}: {exc}")

    def _help(self) -> None:
        self._result(
            "[bold cyan]Commands[/bold cyan]\n"
            "ops/menu       show or hide the operation drawer\n"
            "res/results     hide operation panels and focus the results workspace\n"
            "up/down         scroll results by a few lines\n"
            "pageup/pagedown scroll results by a page; top/bottom jump\n"
            "1..15, c, m    select an operation\n"
            "run / r        run selected operation\n"
            "target <host>  set default target\n"
            "ports <range>  set default ports, e.g. 22,80,443 or 1-1024\n"
            "timeout <sec>  set scan timeout\n"
            "threads <num>  set scan workers\n"
            "iface <name>   set active interface\n"
            "interfaces     list all available interfaces\n"
            "packets        list captured packets in the right panel\n"
            "packet <id>    expand one packet; add full or hex for more detail\n"
            "edit / e       update target and ports interactively\n"
            "clear          clear result workspace\n"
            "quit / q       exit Jasper"
        )

    def _edit_context(self) -> None:
        target = self.console.input(f"[yellow]target[/yellow] [{self.target}]: ").strip()
        if target:
            self.target = target
        ports = self.console.input(f"[yellow]ports[/yellow] [{self.ports}]: ").strip()
        if ports:
            self.ports = ports
        iface = self.console.input(f"[yellow]interface[/yellow] [{self._active_iface()}]: ").strip()
        if iface:
            self.core.ifacelist = [iface]
        self._log("context updated")

    def _show_interfaces(self) -> None:
        """Show every interface Jasper/Scapy can see in the drawer side panel only."""
        try:
            table = self.core.list_interfaces_table()
            self.side_results = f"[bold #7dcfff]Available interfaces[/bold #7dcfff]\n{table}\n\n[dim]Tip: use 'iface <name>' or select Live Sniffing and run.[/dim]"
            self.show_ops = True
            self._log("listed available interfaces in quick-results panel")
        except Exception as exc:
            self.side_results = f"[red]Error while listing interfaces: {exc}[/red]"
            self.show_ops = False
            self.result_scroll = 0
            self._result(f"[red]Error while listing interfaces: {exc}[/red]")
            self._log(f"error: list interfaces: {exc}")

    def _packet_window(self, limit: int = 40) -> List[tuple[int, str]]:
        """Return recent packet indexes and summaries for the side panel."""
        packets = self.last_packets or list(getattr(self.core, "pkt", []) or [])
        if not packets:
            return []
        start = max(0, len(packets) - limit)
        rows: List[tuple[int, str]] = []
        for idx, packet in enumerate(packets[start:], start=start + 1):
            try:
                rows.append((idx, packet.summary()))
            except Exception:
                rows.append((idx, "<unreadable packet>"))
        return rows

    def _show_packet_list(self) -> None:
        rows = self._packet_window(limit=40)
        if not rows:
            self.side_results = "[bold #7dcfff]Captured packets[/bold #7dcfff]\nNo packets are available yet. Run Live Sniffing or read a PCAP first."
            self.show_ops = True
            return
        lines = [
            "[bold #7dcfff]Captured packets[/bold #7dcfff]",
            "Use [bold cyan]packet <id>[/bold cyan] for layered details, [bold cyan]packet <id> full[/bold cyan] for Scapy full view, or [bold cyan]packet <id> hex[/bold cyan] for bytes.",
            "",
        ]
        for idx, summary in rows:
            lines.append(f"[bold #c0caf5]{idx:>4}[/bold #c0caf5]  {summary}")
        self.side_results = "\n".join(lines)
        self.show_ops = True
        self._log("listed captured packets in quick-results panel")

    def _show_packet_detail(self, raw: str) -> None:
        parts = raw.split()
        if len(parts) < 2 or not parts[1].isdigit():
            self.side_results = "[bold #7dcfff]Packet detail[/bold #7dcfff]\nUsage: packet <number> [full|hex]\nExample: packet 3\nExample: packet 3 full"
            self.show_ops = True
            return
        packet_no = int(parts[1])
        mode = parts[2].lower() if len(parts) >= 3 else "layers"
        packets = self.last_packets or list(getattr(self.core, "pkt", []) or [])
        if packet_no < 1 or packet_no > len(packets):
            self.side_results = f"[red]Packet {packet_no} is not available. Current packet range is 1..{len(packets)}.[/red]"
            self.show_ops = False
            self.result_scroll = 0
            return
        pkt = packets[packet_no - 1]
        try:
            summary = pkt.summary()
        except Exception:
            summary = "<summary unavailable>"

        if mode in {"full", "detail", "details", "show"}:
            try:
                body = pkt.show(dump=True)
            except Exception as exc:
                body = f"Unable to render full packet: {exc}"
        elif mode == "hex":
            try:
                raw_bytes = bytes(pkt)
                hex_pairs = raw_bytes.hex(" ")
                chunks = [hex_pairs[i:i + 96] for i in range(0, len(hex_pairs), 96)]
                body = "\n".join(chunks[:80])
                if len(chunks) > 80:
                    body += "\n... truncated ..."
            except Exception as exc:
                body = f"Unable to render packet bytes: {exc}"
        else:
            try:
                layer_names = []
                layer = pkt
                while layer is not None:
                    layer_names.append(layer.__class__.__name__)
                    layer = getattr(layer, "payload", None)
                    if layer is None or layer.__class__.__name__ == "NoPayload":
                        break
                fields = []
                for layer in pkt.layers():
                    try:
                        layer_obj = pkt[layer]
                        field_text = ", ".join(f"{k}={v}" for k, v in layer_obj.fields.items())
                        fields.append(f"[bold #9ece6a]{layer.__name__}[/bold #9ece6a]: {field_text or 'no parsed fields'}")
                    except Exception:
                        pass
                body = "Layers: " + " / ".join(layer_names) + "\n\n" + "\n".join(fields[:30])
            except Exception as exc:
                body = f"Unable to render packet layers: {exc}"

        self.side_results = (
            f"[bold #7dcfff]Packet {packet_no}[/bold #7dcfff]\n"
            f"[bold #c0caf5]Summary[/bold #c0caf5]\n{summary}\n\n"
            f"[bold #c0caf5]Detail[/bold #c0caf5]\n{body}"
        )
        self.show_ops = True
        self._log(f"expanded packet {packet_no} in quick-results panel")

    # ----- wrappers around Jasper functionality -----
    def _default_iface_name(self) -> str:
        iface = getattr(self.core.conf, "iface", "default")
        return getattr(iface, "name", str(iface))

    def _ensure_default_iface(self) -> None:
        try:
            if not getattr(self.core, "ifacelist", None):
                self.core.ifacelist = [self._default_iface_name()]
        except Exception:
            pass

    def _active_iface(self) -> str:
        self._ensure_default_iface()
        active = getattr(self.core, "ifacelist", None)
        if isinstance(active, list):
            return active[0] if len(active) == 1 else ",".join(str(x) for x in active)
        return str(active or self._default_iface_name())

    def _active_iface_value(self) -> Any:
        self._ensure_default_iface()
        active = getattr(self.core, "ifacelist", None)
        if isinstance(active, list) and len(active) == 1:
            return active[0]
        return active or self._default_iface_name()

    def _prompt_target(self) -> str:
        if self.target != "unset":
            val = self.console.input(f"[yellow]target[/yellow] [{self.target}]: ").strip()
            return val or self.target
        target = self.console.input("[yellow]target[/yellow]: ").strip()
        if target:
            self.target = target
        return target

    def _prompt_ports(self) -> str:
        while True:
            val = self.console.input(f"[yellow]ports[/yellow] [{self.ports}]: ").strip()
            candidate = val or self.ports
            try:
                self._parse_ports_safe(candidate)
                if val:
                    self.ports = val
                return self.ports
            except ValueError as exc:
                self.console.print(f"[red]Invalid ports: {exc}[/red]")

    def _parse_ports_safe(self, text: str) -> List[int]:
        raw = (text or "1-1024").replace(" ", "")
        ports = set()
        for part in raw.split(","):
            if not part:
                continue
            if "-" in part:
                pieces = part.split("-", 1)
                if not pieces[0].isdigit() or not pieces[1].isdigit():
                    raise ValueError(f"bad range '{part}'")
                start, end = int(pieces[0]), int(pieces[1])
                if start > end:
                    start, end = end, start
                if start < 1 or end > 65535:
                    raise ValueError("ports must be between 1 and 65535")
                ports.update(range(start, end + 1))
            else:
                if not part.isdigit():
                    raise ValueError(f"bad port '{part}'")
                port = int(part)
                if not 1 <= port <= 65535:
                    raise ValueError("ports must be between 1 and 65535")
                ports.add(port)
        if not ports:
            raise ValueError("no ports selected")
        return sorted(ports)

    def _parse_hosts_safe(self, text: str) -> List[str]:
        text = (text or "").strip()
        if not text:
            raise ValueError("target cannot be empty")
        hosts = self.core.parse_hosts(text)
        if not hosts:
            raise ValueError("no valid host targets found")
        if len(hosts) > 1024:
            raise ValueError("target list is too large; use 1024 hosts or fewer")
        return hosts

    def _connect_scan_host(self, host: str, ports: List[int]) -> List[tuple[int, str]]:
        try:
            address = socket.gethostbyname(host)
        except socket.gaierror as exc:
            raise ValueError(f"cannot resolve {host}: {exc}")

        def check(port: int) -> Optional[tuple[int, str]]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.scan_timeout)
                try:
                    if sock.connect_ex((address, port)) == 0:
                        return port, self.core.service_name(port)
                except OSError:
                    return None
            return None

        open_ports: List[tuple[int, str]] = []
        workers = max(1, min(self.scan_threads, len(ports)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(check, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        return sorted(open_ports, key=lambda item: item[0])

    def _run_live_sniff(self):
        """Run live sniffing with the active context only.

        This operation must never open hidden prompts. The command reader owns all
        keyboard input, so prompting here makes the dashboard look frozen. Users
        change settings with commands such as `interfaces`, `iface en0`,
        `count 50`, `timeout 10`, and `view detailed` before running.
        """
        iface = self._active_iface_value()
        if isinstance(iface, list):
            if len(iface) == 1:
                iface = iface[0]
            else:
                raise ValueError("live sniffing needs one active interface; use iface <name>")
        iface = str(iface)
        if not iface or iface.lower() in {"none", "unset"}:
            iface = self._default_iface_name()
            self.core.ifacelist = [iface]

        available = set(self.core.get_if_list())
        if iface not in available:
            raise ValueError(f"active interface '{iface}' was not found; run interfaces then iface <name>")

        count = int(self.sniff_count)
        timeout = float(self.sniff_timeout)
        detailed = bool(self.sniff_detailed)
        self.side_results = (
            f"[bold #7dcfff]Live Sniffing[/bold #7dcfff]\n"
            f"iface: {iface}\ncount: {count or 'timeout-only'}\ntimeout: {timeout:.1f}s\n"
            f"view: {'detailed' if detailed else 'summary'}\n\n"
            "Capture is running. Results will appear when the count or timeout completes."
        )

        summaries: List[str] = []
        self.capture_state = "running"
        print(
            f"Live sniffing started on {iface} | count={count or 'timeout-only'} | "
            f"timeout={timeout:.1f}s | mode={'detailed' if detailed else 'summary'}"
        )
        try:
            def on_packet(packet):
                try:
                    summaries.append(packet.summary())
                except Exception:
                    summaries.append("<unreadable packet>")

            self.core.pkt = self.core.sniff(
                iface=iface,
                count=count,
                timeout=timeout,
                prn=on_packet,
                store=True,
            )
            self.last_packets = list(self.core.pkt or [])
            self.last_packet_summaries = summaries
            captured = len(self.last_packets)
            self.packet_count = captured
            self._refresh_packet_stats()
            summary = (
                f"Captured {captured} packet(s) on {iface}.\n"
                f"Protocol mix: TCP {self.protocol_counts['TCP']}, UDP {self.protocol_counts['UDP']}, "
                f"ICMP {self.protocol_counts['ICMP']}, OTHER {self.protocol_counts['OTHER']}."
            )
            recent_rows = self._packet_window(limit=25)
            recent = "\n".join(f"[bold #c0caf5]{idx:>4}[/bold #c0caf5]  {text}" for idx, text in recent_rows)
            if not recent:
                recent = "No packets captured before count/timeout completed."
            self.side_results = (
                f"[bold #7dcfff]Live sniffing result[/bold #7dcfff]\n{summary}\n\n"
                "[bold #c0caf5]Recent packets[/bold #c0caf5]\n"
                f"{recent}\n\n"
                "[dim]Use: packets, packet <id>, packet <id> full, or packet <id> hex.[/dim]"
            )
            print(summary)
            print("Packet list is in the right quick-results panel. Use: packets, packet <id>, packet <id> full, or packet <id> hex.")
            return self.core.pkt
        finally:
            self.capture_state = "stopped"

    def _run_read_pcap(self):
        result = self.core.readPCAP(self.core.ask_file_open())
        if result is not None:
            self.pcap_name = "loaded capture"
        return result

    def _run_save_pcap(self):
        return self.core.savePCAP(self.core.ask_file_save(), self.core.pkt)

    def _run_dataframe(self):
        self.core.df = self.core.convertToDataframe(self.core.pkt)
        return self.core.df

    def _run_arp(self):
        network = self.console.input("[yellow]network/CIDR[/yellow]: ").strip()
        self.core.ans_arpPing, self.core.unans_arpPing = self.core.arpPing(network)
        return self.core.ans_arpPing

    def _run_single_ports(self):
        host = self._prompt_target()
        if not host:
            raise ValueError("target is required for single-host scanning")
        ports = self._parse_ports_safe(self._prompt_ports())
        print(f"Scanning {host} on {len(ports)} TCP port(s) with timeout={self.scan_timeout:.1f}s, workers={self.scan_threads}")
        found = self._connect_scan_host(host, ports)
        table = self.core.prettytable.PrettyTable(["Host", "Port Number", "Port Name", "Status"])
        for port, name in found:
            table.add_row([host, port, name, "Open"])
        self.core.scanPortSingleTable = table
        rendered = table.get_string() if table._rows else f"No open TCP ports found on {host} for {self.ports}."
        self.side_results = f"[bold cyan]Single-host scan[/bold cyan]\n{rendered}"
        self.show_ops = True
        print(rendered)
        return table

    def _run_mass_ports(self):
        default = "" if self.target == "unset" else self.target
        targets = self.console.input(f"[yellow]targets/CIDR/comma list[/yellow] [{default}]: ").strip() or default
        hosts = self._parse_hosts_safe(targets)
        ports = self._parse_ports_safe(self._prompt_ports())
        print(f"Scanning {len(hosts)} host(s), {len(ports)} TCP port(s) each, timeout={self.scan_timeout:.1f}s, workers={self.scan_threads}")
        table = self.core.prettytable.PrettyTable(["IP Address", "Port Number", "Port Name", "Status"])
        scanned = 0
        for host in hosts:
            scanned += 1
            print(f"[{scanned}/{len(hosts)}] Scanning {host}")
            try:
                for port, name in self._connect_scan_host(host, ports):
                    table.add_row([host, port, name, "Open"])
            except ValueError as exc:
                print(f"Skipping {host}: {exc}")
        self.core.scanPortMassTable = table
        rendered = table.get_string(sortby="IP Address") if table._rows else "No open TCP ports found for the selected targets and port range."
        self.side_results = f"[bold cyan]Mass scan[/bold cyan]\n{rendered}"
        self.show_ops = True
        print(rendered)
        return table

    def _run_trace(self):
        target = self._prompt_target()
        self.core.tracerouteTable, self.core.tracerouteList = self.core.tcpTraceRoute(target)
        return self.core.tracerouteTable

    def _run_dns(self):
        target = self._prompt_target()
        return self.core.resolveDNS(target)

    def _run_geo(self):
        return self.core.geoShow(self.core.tracerouteList, passive=0)

    def _run_structure(self):
        return self.core.packetStructure(self.core.pkt)

    def _run_conversations(self):
        return self.core.packetConversations()

    def _run_compare(self):
        return self.core.crossTwoPCAPS()

    def _run_vuln(self):
        return self.core.vulnerabilityScanning()

    def _run_save_vuln(self):
        return self.core.saveVulnerabilityList()

    def _run_config(self):
        return self.core.setConfiguration()

    def _run_modules(self):
        return self.core.listModules()

    def _run_new_module(self):
        return self.core.addNewModule()

    def _run_about(self):
        return self.core.aboutJasper()

    # ----- state helpers -----
    def _refresh_live_stats(self) -> None:
        """Refresh cheap live metrics used by the top panels."""
        self._network_rates()
        self._refresh_packet_stats()

    def _refresh_packet_stats(self) -> None:
        packets = getattr(self.core, "pkt", None)
        if packets is None:
            return
        try:
            self.packet_count = len(packets)
            self.packet_ticks = (self.packet_ticks + [min(999, self.packet_count)])[-32:]
            counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
            TCP = self.core.TCP
            UDP = self.core.UDP
            IP = self.core.IP
            for p in packets[-500:]:
                if TCP in p:
                    counts["TCP"] += 1
                elif UDP in p:
                    counts["UDP"] += 1
                elif IP in p and getattr(p[IP], "proto", None) == 1:
                    counts["ICMP"] += 1
                else:
                    counts["OTHER"] += 1
            self.protocol_counts = counts
        except Exception:
            pass

    def _timestamp(self) -> str:
        return dt.datetime.now().strftime("%H:%M:%S")

    def _log(self, message: str) -> None:
        self.history.append(f"[dim]{self._timestamp()}[/dim]  {message}")

    def _scroll_results(self, delta: int) -> None:
        lines = self._result_lines()
        max_lines = max(18, self.console.height - (13 if not self.show_ops else 22))
        max_scroll = max(0, len(lines) - max_lines)
        self.result_scroll = max(0, min(max_scroll, self.result_scroll + delta))
        if self.result_scroll == 0:
            self._log("results scrolled to bottom")
        elif self.result_scroll == max_scroll:
            self._log("results scrolled to top")
        else:
            self._log(f"results scroll offset {self.result_scroll} line(s)")

    def _result(self, message: str) -> None:
        self.results.append(f"[dim]{self._timestamp()}[/dim]  {message}")
        # New results should be visible immediately unless the user is reading
        # older output; keep the workspace pinned to the bottom by default.
        if self.result_scroll == 0:
            self.result_scroll = 0
