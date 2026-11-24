# Usage

## Install

```bash
git clone https://github.com/NicholasVormack/ReconX.git
cd ReconX
python3 -m reconx --version        # runs straight from the checkout, no install
```

Optional, for the `reconx` command on your PATH:

```bash
python3 -m pip install --user -e .
reconx --version
```

Optional, for service/version detection:

```bash
brew install nmap        # macOS
sudo apt install nmap    # Debian/Ubuntu
```

ReconX runs without Nmap and says so. Nothing else is required.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `target` | – | Hostname or IP address |
| `--ports` | 31 curated ports | Ports, ranges and names: `22,80,8000-8010,ssh` |
| `--top N` | – | Take the first N ports of the default list |
| `--timeout` | `2.0` | Per-port timeout in seconds |
| `--threads` | `64` | Worker threads |
| `--no-banner` | off | Skip banner grabbing (much faster on a wide range) |
| `--no-nmap` | off | Skip Nmap enrichment |
| `--out` | `reconx-reports` | Report directory |
| `--formats` | `json,csv,html,md` | Any subset of those four |
| `--discover CIDR` | – | Sweep a network for live hosts instead of scanning |
| `--fail-on` | `none` | Exit code 2 when a finding at this severity exists |
| `--quiet` | off | Suppress per-port detail lines |
| `--version` | – | Print the version |

Exit codes: `0` clean, `1` usage or target error, `2` threshold met.

## Recipes

**Audit a host you own before exposing it**

```bash
python3 -m reconx 10.0.0.42 --ports 1-1024 --formats html,json
open reconx-reports/10.0.0.42-*.html
```

**Fast check of the usual suspects**

```bash
python3 -m reconx example.com --ports 21,22,23,80,443,445,3389,8080 --no-banner
```

**Find the live machines on a network first**

```bash
python3 -m reconx --discover 192.168.1.0/24
```

Then scan what answered:

```bash
for host in $(python3 -m reconx --discover 192.168.1.0/24 | tail -n +2); do
  python3 -m reconx "$host" --quiet --no-nmap
done
```

**Use it as a gate in CI**

```bash
# Fail the build if anything high or critical is reachable from the runner.
python3 -m reconx staging.internal --ports 1-10000 --no-banner --fail-on high \
  --formats json --out artifacts/
```

**Wide sweep without Nmap**

```bash
python3 -m reconx 10.0.0.5 --ports 1-65535 --no-banner --no-nmap --threads 256
```

## Library use

```python
from reconx import parse_ports, scan_host, write_reports

result = scan_host("10.0.0.42", ports=parse_ports("22,80,443"), timeout=1.0)

print(result.risk_grade, result.risk_score)
for finding in result.open_findings:
    print(finding.port, finding.service, finding.severity.value, finding.note)

write_reports(result, "reports", formats=("json", "html"))
```

## GUI

```bash
python3 -m reconx.gui
```

Enter a target and ports, hit **Scan**, then **Save report**. The scan runs on a
worker thread, so the window stays responsive.

## Reading a report

The HTML report is a single file with no external assets, so it can be emailed or
attached to a ticket. The risk grade is a summary of the weighted findings:

| Grade | Score | Meaning |
| --- | --- | --- |
| A | 0 | Nothing notable exposed |
| B | 1–3 | Low-severity services only |
| C | 4–8 | Something worth fixing this sprint |
| D | 9–16 | High-severity exposure |
| F | 17+ | Critical exposure: unauthenticated database, RDP, telnet |

An open port is evidence, not proof of exploitability. The report says what is
reachable and why it matters; confirming impact is a separate, authorized step.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

55 tests, no network access required: the live-scan tests bind their own local
socket.
