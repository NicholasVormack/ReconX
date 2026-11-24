# Architecture

ReconX is five small modules with one direction of dependency. Nothing imports
the CLI, and nothing touches the network at import time.

```
services.py  ──── pure ────▶  port registry, banner fingerprints, risk rules
     │
     ▼
engine.py    ──── sockets ─▶  port probing, banner grab, TLS inspect, host sweep
     │
     ├──────────▶ nmapbridge.py   optional, one nmap run per host
     ▼
report.py    ──── files ───▶  JSON / CSV / Markdown / HTML
     │
     ▼
cli.py  ·  gui.py             two front ends over the same engine
```

## Module responsibilities

| Module | Owns | Talks to |
| --- | --- | --- |
| `services.py` | Port→service map, banner signature table, risk rules, probe selection | nothing |
| `engine.py` | Thread pool, socket probes, TLS handshake, `ScanResult` | `services` |
| `nmapbridge.py` | Locating `nmap`, running `-sV`, parsing `-oX` XML | nothing |
| `report.py` | Rendering `ScanResult` into four formats | `engine`, `services` |
| `cli.py` | Argument parsing, terminal output, exit codes | all of the above |
| `gui.py` | Tkinter shell, worker thread, report button | `engine`, `report` |

## Data flow for one scan

1. `parse_ports()` expands the port specification into a concrete sorted list.
2. `validate_target()` resolves the host once and rejects anything that is not a
   hostname or IP literal.
3. `ThreadPoolExecutor` submits one `probe_port` task per port, capped by
   `--threads`. Each task connects, records latency, optionally grabs a banner,
   and classifies the result.
4. Findings are sorted by port, then by severity for display and reporting.
5. `nmapbridge.enrich()` runs **once** for the host, against the ports that were
   already found open.
6. `report.write_reports()` writes the requested formats into a timestamped
   directory.

## Design decisions

**No runtime dependencies.** Everything is standard library: `socket`, `ssl`,
`concurrent.futures`, `csv`, `json`, `xml.etree`, `argparse`, `tkinter`. A
security tool that needs a package manager to run is a security tool people do
not run.

**No work at import.** The first version created a `Scans/` directory as a module
side effect, which made the code untestable and littered empty folders. Scan
state now lives in `ScanResult`.

**Classification is pure.** Everything that decides severity lives in
`services.py` as functions over `(port, banner)`. That is why the risk rules can
be unit tested by the hundred without opening a socket, and why adding a rule is
a one-line change with an obvious test.

**Nmap is optional and runs once.** The original code called
`subprocess.run(["nmap", "-O", "-sV", target])` from inside the per-port worker
and called it twice per open port. Eight open ports meant sixteen full Nmap
runs, each requiring root for `-O`. Now Nmap runs once, only on open ports, only
if installed, and its XML is parsed rather than scraped with string matching.

**Services that speak first are not interrupted.** SSH, FTP, SMTP, MySQL and
friends send a greeting on connect. Sending an HTTP request at them corrupts the
banner, so `probe_for()` returns `None` for those ports and ReconX just listens.

**Host discovery needs neither root nor ICMP.** A connect attempt that is
explicitly refused still proves the host is alive, so `discover_hosts()` treats
`ECONNREFUSED` as evidence of life. That finds hosts that block ping, on macOS
and Linux, without raw sockets.

**Bounded concurrency.** Worker count is capped at both `--threads` and the port
count, so a 65,535-port scan does not spawn 65,535 threads.

## Report schema

`reconx.report/2` is stable and versioned:

```json
{
  "tool": "ReconX",
  "schema": "reconx.report/2",
  "target": "10.0.0.5",
  "address": "10.0.0.5",
  "ports_probed": [22, 80, 443],
  "risk_score": 4,
  "risk_grade": "B",
  "findings": [
    { "port": 445, "state": "open", "service": "smb", "severity": "high",
      "note": "...", "product": "Samba 4.13", "banner": "...", "latency_ms": 1.8 }
  ],
  "nmap": { "services": [], "os": [] },
  "disclaimer": "Only scan systems you own or have written authorization to test."
}
```

Consumers should key off `schema` and ignore unknown fields.

## Extending

- **New service name** → add to `SERVICE_NAMES`.
- **New risk rule** → add to `PORT_RISK` with a rationale sentence; the note is
  what makes the report useful.
- **New fingerprint** → add a `(regex, product, severity_hint)` row to
  `BANNER_SIGNATURES`. First match wins, so put specific patterns above general
  ones.
- **New probe** → add a branch to `probe_for()`.
- **New report format** → add a `build_*()` function in `report.py` and a branch
  in `write_reports()`.
