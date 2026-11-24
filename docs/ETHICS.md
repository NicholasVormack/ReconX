# Authorized use

ReconX sends network traffic to hosts you point it at. That is the whole point,
and it is also the whole risk.

## The rule

**Only scan systems you own or have written permission to test.**

In the United States, unauthorized scanning can violate the Computer Fraud and
Abuse Act (18 U.S.C. § 1030) even when nothing is exploited and nothing is
damaged. Equivalent laws exist in the UK (Computer Misuse Act 1990), the EU
(Directive 2013/40/EU), Canada (Criminal Code s. 342.1) and most other
jurisdictions. "It was only a port scan" is not a defence.

## What that looks like in practice

- **Your own machine or home network.** Fine, scan it as often as you like.
- **A client engagement.** Get it in writing, and keep the scope explicit: which
  CIDR ranges, which window, who to call if something breaks.
- **A lab, CTF, or deliberately vulnerable target.** Fine. `scanme.nmap.org` is
  published by the Nmap project for exactly this purpose, at low volume.
- **A bug bounty program.** Fine *within the program's stated scope*. Read the
  scope before you scan; out-of-scope hosts can disqualify the whole report.
- **A public IP you do not own.** No. Not even a single port.
- **The network at work, on a laptop IT gave you.** No, unless IT says yes.

## Things ReconX deliberately does not do

- No exploitation, no credential attacks, no brute forcing.
- No stealth or evasion modes. Evading detection on a network you are authorized
  to test is unnecessary, and on one you are not, it is evidence of intent.
- No payload delivery, no persistence, no lateral movement.

ReconX is a *reporting* tool: it tells you what is exposed and why it matters, so
the exposure can be closed.

## Handling the output

Scan results describe the internals of a network: hostnames, service versions,
TLS certificate subjects. Treat a report like the asset inventory it is.

- Do not commit scan output to a public repository. `reconx-reports/` is
  gitignored for this reason.
- Share reports over a channel appropriate to their contents.
- Delete engagement output when the engagement ends, unless the contract says to
  retain it.

## If you find something serious

A critical finding on infrastructure you do not own is not a licence to keep
looking. Stop, preserve what you already have, and contact the owner — or the
relevant CERT — through their published security contact. Most organizations
have a `security.txt` or a `security@` address, and a responsible report is worth
more to them than silence.
