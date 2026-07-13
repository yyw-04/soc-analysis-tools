# SOC Analysis Tools

Defensive utilities for SOC investigation, traffic analysis, and incident reporting.

## Tools

### [Defensive C2/PCAP Tools](c2-pcap-analyzer/)

Modular tools for:

- hosts, protocols, ports, DNS, and clear-text HTTP metadata;
- port-scan and periodic-communication candidates;
- high-volume flows requiring exfiltration review;
- automatic bounded detection of encoded HTTP query values;
- analyst-selected Base64, Base64URL, hexadecimal, and URL decoding;
- first-class offline RSA, AES-CBC, and HMAC analysis when exact keys and layouts are available;
- structured JSON reporting.

## Safety

These tools are for defensive analysis. They do not execute captured payloads or contact observed infrastructure. Handle malicious evidence in an isolated environment and follow your organization's evidence-handling procedures.

## Judgement rule

A match is not proof of malicious activity, and no match does not prove safety. Combine multiple evidence sources before assigning a verdict.
