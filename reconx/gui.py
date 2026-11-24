"""Optional Tkinter front end for ReconX.

    python -m reconx.gui

The window is a thin shell over ``engine.scan_host``: the scan runs on a worker
thread so the UI stays responsive, results land in a sortable table, and any
report format can be written with one click. The earlier version accepted a
"scan type" dropdown that was never read and called the engine with the wrong
argument count, so every GUI scan raised ``TypeError``.
"""

from __future__ import annotations

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from . import __version__
from .engine import ScanResult, parse_ports, scan_host
from .report import write_reports
from .services import Severity

SEVERITY_TAGS = {
    Severity.CRITICAL: "#ff3b5c",
    Severity.HIGH: "#ff8a3d",
    Severity.MEDIUM: "#c8a600",
    Severity.LOW: "#1f7fa8",
    Severity.INFO: "#6b7280",
}


class ReconXApp:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.result: Optional[ScanResult] = None
        self.scanning = False

        root.title(f"ReconX {__version__} - Port & Surface Scanner")
        root.geometry("920x620")
        root.minsize(760, 520)

        self._build_toolbar()
        self._build_table()
        self._build_status()

    # ------------------------------------------------------------------ UI

    def _build_toolbar(self) -> None:
        frame = ttk.Frame(self.root, padding=(12, 10))
        frame.pack(fill="x")

        ttk.Label(frame, text="Target").grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frame, textvariable=self.target_var, width=26).grid(
            row=0, column=1, padx=(6, 14)
        )

        ttk.Label(frame, text="Ports").grid(row=0, column=2, sticky="w")
        self.ports_var = tk.StringVar(value="22,80,443,3000,8080")
        ttk.Entry(frame, textvariable=self.ports_var, width=30).grid(
            row=0, column=3, padx=(6, 14)
        )

        ttk.Label(frame, text="Timeout").grid(row=0, column=4, sticky="w")
        self.timeout_var = tk.StringVar(value="1.5")
        ttk.Entry(frame, textvariable=self.timeout_var, width=6).grid(
            row=0, column=5, padx=(6, 14)
        )

        self.scan_button = ttk.Button(frame, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=6, padx=(0, 6))
        ttk.Button(frame, text="Save report", command=self.save_report).grid(row=0, column=7)

    def _build_table(self) -> None:
        container = ttk.Frame(self.root, padding=(12, 0))
        container.pack(fill="both", expand=True)

        columns = ("port", "service", "severity", "product", "latency", "note")
        self.table = ttk.Treeview(container, columns=columns, show="headings", height=16)
        headings = {
            "port": ("Port", 70),
            "service": ("Service", 120),
            "severity": ("Severity", 90),
            "product": ("Product", 170),
            "latency": ("Latency", 80),
            "note": ("Why it matters", 340),
        }
        for column, (label, width) in headings.items():
            self.table.heading(column, text=label)
            self.table.column(column, width=width, anchor="w")

        for severity, color in SEVERITY_TAGS.items():
            self.table.tag_configure(severity.value, foreground=color)

        scroll = ttk.Scrollbar(container, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_status(self) -> None:
        frame = ttk.Frame(self.root, padding=(12, 8))
        frame.pack(fill="x")
        self.status_var = tk.StringVar(value="Ready. Only scan systems you are authorized to test.")
        ttk.Label(frame, textvariable=self.status_var).pack(side="left")

    # --------------------------------------------------------------- actions

    def start_scan(self) -> None:
        if self.scanning:
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("ReconX", "Enter a target host or IP address.")
            return
        try:
            ports = parse_ports(self.ports_var.get())
            timeout = float(self.timeout_var.get())
        except ValueError as exc:
            messagebox.showerror("ReconX", str(exc))
            return

        self.scanning = True
        self.scan_button.state(["disabled"])
        self.table.delete(*self.table.get_children())
        self.status_var.set(f"Scanning {target} ({len(ports)} ports)...")

        threading.Thread(
            target=self._scan_worker, args=(target, ports, timeout), daemon=True
        ).start()

    def _scan_worker(self, target: str, ports: List[int], timeout: float) -> None:
        try:
            result = scan_host(target, ports=ports, timeout=timeout, banner=True)
        except Exception as exc:  # surfaced in the UI, never swallowed
            self.root.after(0, lambda: self._finish(None, str(exc)))
            return
        self.root.after(0, lambda: self._finish(result, None))

    def _finish(self, result: Optional[ScanResult], error: Optional[str]) -> None:
        self.scanning = False
        self.scan_button.state(["!disabled"])
        if error or result is None:
            self.status_var.set(f"Scan failed: {error}")
            messagebox.showerror("ReconX", f"Scan failed: {error}")
            return

        self.result = result
        for finding in result.open_findings:
            self.table.insert(
                "",
                "end",
                values=(
                    finding.port,
                    finding.service,
                    finding.severity.value,
                    finding.product or "-",
                    f"{finding.latency_ms:.0f} ms",
                    finding.note or "-",
                ),
                tags=(finding.severity.value,),
            )
        self.status_var.set(
            f"{result.target}: {len(result.open_findings)} open of {len(result.ports)} probed "
            f"in {result.duration_seconds:.1f}s - grade {result.risk_grade}"
        )

    def save_report(self) -> None:
        if not self.result:
            messagebox.showinfo("ReconX", "Run a scan first.")
            return
        directory = filedialog.askdirectory(title="Choose a report directory")
        if not directory:
            return
        try:
            paths = write_reports(self.result, directory)
        except OSError as exc:
            messagebox.showerror("ReconX", f"Could not write report: {exc}")
            return
        self.status_var.set(f"Wrote {len(paths)} report file(s) to {os.path.abspath(directory)}")
        messagebox.showinfo("ReconX", "Reports written:\n" + "\n".join(paths.values()))


def main() -> None:
    root = tk.Tk()
    ReconXApp(root)
    root.mainloop()


if __name__ == "__main__":  # pragma: no cover
    main()
