# Security Policy

## Reporting a Vulnerability

SigCorr is a security analysis tool. If you discover a vulnerability in SigCorr itself (not in the telecom protocols it analyzes), please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **shreyas@sigcorr.io** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours and a detailed response within 7 days.

## Scope

This policy covers vulnerabilities in:

- SigCorr's Java source code
- The tshark bridge and command execution
- Configuration parsing
- Dependencies (report upstream, but let us know)

This policy does **not** cover:

- SS7/Diameter/GTP protocol vulnerabilities (these are the attacks SigCorr *detects*)
- Vulnerabilities in tshark/Wireshark itself (report to [Wireshark Security](https://www.wireshark.org/security/))

## Responsible Use

SigCorr is designed for **defensive** security analysis — detecting attacks on telecom networks. It performs passive pcap analysis only and does not inject traffic.

Use SigCorr only on networks and captures you are authorized to analyze.
