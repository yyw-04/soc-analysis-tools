# C2/PCAP Analyzer

A defensive, read-only Python helper for SOC analysts reviewing suspicious PCAP or PCAPNG files. It summarizes network activity and highlights investigation candidates without executing or extracting captured payloads.

> **Safety first:** Treat every malicious capture as untrusted evidence. Use an isolated analysis VM or container. This tool never contacts observed infrastructure, executes payloads, or writes packet payloads to disk.

## What it checks

- Input SHA-256, capture size, time range, and packet count
- Source and destination IP addresses, scopes, protocols, and ports
- DNS queries and answers
- Clear-text HTTP request lines and `Host` headers only
- Vertical port-scan candidates: one source, one destination, many ports
- Horizontal scan candidates: one source, one port, many destinations
- Periodic communication or beaconing candidates
- High-volume directional flows that may need exfiltration review
- Analyst-selected Base64, Base64URL, hexadecimal, or URL decoding

The detections are leads, not verdicts. Authorized scanners, monitoring systems, update services, backups, and normal applications can produce similar patterns.

## Safety boundaries

The analyzer:

- opens the capture read-only;
- does not execute or import captured content;
- does not extract files, scripts, shellcode, or packet bodies;
- does not make DNS, HTTP, TLS, or other network connections;
- does not automatically decrypt framework-specific C2 traffic;
- writes only the JSON path explicitly supplied with `--json-out`;
- limits file size, packet count, HTTP metadata length, and decoding input.

## Requirements

- Python 3.10 or newer
- No third-party runtime packages

The built-in parser supports classic PCAP plus common PCAPNG captures containing Enhanced Packet Blocks. Supported link types are Ethernet, raw IPv4/IPv6, Linux cooked capture v1, and Linux cooked capture v2.

## Installation

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Analyze a capture

Human-readable summary:

```bash
python c2_pcap_analyzer.py analyze suspicious.pcap
```

Summary plus a structured JSON report:

```bash
python c2_pcap_analyzer.py analyze suspicious.pcap \
  --json-out reports/suspicious-report.json
```

Windows PowerShell:

```powershell
python .\c2_pcap_analyzer.py analyze .\suspicious.pcap `
  --json-out .\reports\suspicious-report.json
```

Stricter beacon review and a larger packet limit:

```bash
python c2_pcap_analyzer.py analyze suspicious.pcap \
  --max-packets 1000000 \
  --beacon-min-events 10 \
  --beacon-max-cv 0.12 \
  --json-out report.json
```

## Decode an analyst-selected field

Base64:

```bash
python c2_pcap_analyzer.py decode \
  --encoding base64 \
  --value "SGVsbG8="
```

URL-safe Base64:

```bash
python c2_pcap_analyzer.py decode \
  --encoding base64url \
  --value "SGVsbG8td29ybGQ"
```

Hexadecimal:

```bash
python c2_pcap_analyzer.py decode \
  --encoding hex \
  --value "48656c6c6f"
```

URL encoding:

```bash
python c2_pcap_analyzer.py decode \
  --encoding url \
  --value "%48%65%6c%6c%6f"
```

Decoding is not decryption. Base64, Base64URL, hexadecimal, and URL encoding only change representation. Framework-specific RSA, AES, HMAC, nonce/IV, transforms, and session keys must be handled separately when the lab or investigation provides the correct values and authorization.

## Important options

| Option | Purpose | Default |
| --- | --- | ---: |
| `--max-packets` | Stop after this many packets | `250000` |
| `--max-file-mb` | Refuse captures larger than this | `2048` |
| `--scan-window` | Scan detection window in seconds | `60` |
| `--scan-port-threshold` | Distinct ports for a vertical-scan candidate | `20` |
| `--scan-host-threshold` | Distinct hosts for a horizontal-scan candidate | `20` |
| `--beacon-min-events` | Minimum repeated events for beacon review | `6` |
| `--beacon-min-interval` | Minimum average interval in seconds | `2` |
| `--beacon-max-interval` | Maximum average interval in seconds | `3600` |
| `--beacon-max-cv` | Maximum interval coefficient of variation | `0.20` |
| `--large-transfer-mb` | Directional-flow size requiring review | `5` |
| `--http-limit` | Maximum clear-text HTTP metadata records | `200` |

## Reading the findings

### Port-scan candidate

Investigate:

- whether the source is an approved scanner or administrator host;
- whether TCP SYN packets received responses;
- which ports and assets were targeted;
- whether enumeration was followed by authentication or exploitation.

### Beacon candidate

Investigate:

- timing regularity, jitter, duration, and destination rarity;
- related DNS queries, TLS certificates, JA3/JA4, HTTP headers, and URI patterns;
- the process and user responsible for the connection;
- threat intelligence and expected business activity.

A regular interval increases suspicion but does not automatically prove command and control.

### Large-transfer candidate

Investigate:

- transfer direction and expected application behavior;
- destination ownership, domain, and reputation;
- protocol, time range, user, host, and associated process;
- whether compression, archiving, staging, or credential access occurred first.

## Recommended evidence workflow

1. Work from a copy and record the original capture hash.
2. Keep the capture in an isolated evidence directory.
3. Run the analyzer and save JSON outside the evidence directory.
4. Validate candidates in Wireshark, Zeek, Suricata, EDR, DNS, proxy, and identity logs.
5. Record scope, user impact, and a timeline.
6. Preserve suspicious objects as inert evidence only when your procedure requires it; never execute them.

## Limitations

- Encrypted traffic content remains encrypted unless valid keys are supplied to another authorized workflow.
- The helper does not identify a C2 framework automatically.
- Retransmissions, NAT, asymmetric captures, packet loss, and sampling affect results.
- UDP periodicity may identify expected DNS, telemetry, or time synchronization.
- Clear-text HTTP parsing retains only request metadata and intentionally ignores bodies.
- No detection only lowers suspicion; it does not prove the traffic is safe.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The tests generate synthetic packets only. They do not download malware, contact external systems, or execute captured content.

## Exit codes

- `0` — analysis or decoding completed
- `2` — invalid input, unsafe overwrite attempt, size limit, parsing error, or invalid option

## Analyst judgement rule

Do not decide from one indicator. Combine timing, endpoints, ports, DNS, HTTP/TLS metadata, process telemetry, identity, threat intelligence, user impact, scope, and business context before assigning a verdict.
