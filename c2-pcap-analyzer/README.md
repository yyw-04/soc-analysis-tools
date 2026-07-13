# Defensive C2/PCAP Tools

Two modular Python tools for SOC analysts: an automatic, read-only PCAP analyzer and a separate offline decryption tool for analyst-selected C2 fields.

> **Safety first:** Treat every capture, key, and decoded value as untrusted evidence. Use an isolated analysis VM or container. The tools never contact observed infrastructure, execute payloads, or automatically extract captured files.

## Choose the tool

| Tool | Purpose | Runtime |
| --- | --- | --- |
| `c2_pcap_analyzer.py` | Automatic PCAP/PCAPNG metadata analysis, scan and beacon leads, encoded HTTP query detection, triage, and JSON reporting | Python standard library |
| `c2_crypto_helper.py` | Offline RSA or AES-CBC decryption and HMAC verification for one analyst-selected field | `cryptography` |

Both tools are installed together. The analyst chooses which Python file to run. The decryption tool is first-class, but it is not a universal C2 decryptor: it does not recover keys, infer framework profiles, or guess cipher layouts.

## Project structure

```text
c2-pcap-analyzer/
|-- c2_pcap_analyzer.py       # Automatic passive analyzer launcher
|-- c2_crypto_helper.py       # Offline decryption launcher
|-- pyproject.toml            # Runtime and development dependencies
|-- soc_c2/
|   |-- analysis.py           # Scan, beacon, and transfer heuristics
|   |-- automation.py         # Automatic stage coordination and triage
|   |-- capture.py            # Bounded PCAP/PCAPNG reader
|   |-- cli.py                # PCAP analyzer CLI
|   |-- crypto.py             # Tested RSA, AES-CBC, and HMAC primitives
|   |-- crypto_cli.py         # Decryption CLI
|   |-- models.py             # Configuration, models, and safety limits
|   |-- protocols.py          # IP, TCP/UDP, DNS, and HTTP metadata parsing
|   |-- reporting.py          # Human and JSON output
|   |-- transforms.py         # Base64, Base64URL, URL, and hex transforms
|   `-- utils.py              # Hashing, timestamps, IP scope, and previews
`-- tests/
```

## Safety boundaries

The tools:

- open captures and selected inputs read-only;
- never execute or import captured content;
- never contact IP addresses, domains, or URLs found in evidence;
- never automatically extract captured files;
- never create standalone decrypted payload files;
- display and report only bounded decoded or decrypted previews;
- enforce limits on captures, packets, key files, inputs, and previews;
- treat every detection as an investigation lead, not a verdict.

## Installation

Python 3.10 or newer is required. Install both tools and the required `cryptography` runtime:

```bash
python -m pip install .
```

Development and tests:

```bash
python -m pip install ".[dev]"
```

Dependencies are defined once in `pyproject.toml`: `cryptography` is a normal runtime dependency and `pytest` is the only development extra.

## Automatic PCAP analysis

```bash
python c2_pcap_analyzer.py analyze suspicious.pcap
```

Save a structured report and control the decoded preview size:

```bash
python c2_pcap_analyzer.py analyze suspicious.pcap \
  --decode-preview-bytes 128 \
  --json-out reports/suspicious-report.json
```

The analyzer reads the capture once. It records the SHA-256, time range, endpoints, protocols, destination ports, DNS, and clear-text HTTP request metadata. It highlights vertical scans, horizontal scans, periodic communication, and large directional flows. It also checks retained HTTP query values for bounded Base64, Base64URL, hexadecimal, or URL-decoding candidates and produces an explainable triage score.

Automatic decoding is a lead only. Ordinary applications also use encoded identifiers. The analyzer intentionally avoids automatic path-segment decoding because ordinary asset names and slugs create too many false positives.

### Important analyzer limitations

- Regular timing can also come from updates, telemetry, monitoring, or backups.
- Flow byte counts are capture-observed bytes, not proof of exfiltration.
- Retransmissions, NAT, asymmetric capture, packet loss, and sampling affect results.
- Encrypted application content remains encrypted.
- No detection only lowers suspicion; it does not prove safety.

## Decode one selected representation

Base64, Base64URL, hexadecimal, and URL encoding are transformations, not encryption.

```bash
python c2_pcap_analyzer.py decode --encoding base64 --value "SGVsbG8="
python c2_pcap_analyzer.py decode --encoding hex --value "48656c6c6f"
python c2_pcap_analyzer.py decode --encoding url --value "%48%65%6c%6c%6f"
```

## AES-CBC decryption tool

Set only values confirmed by the lab, malware configuration, memory evidence, or framework documentation.

```bash
python c2_crypto_helper.py aes-cbc \
  --value "PASTE_BASE64_CIPHERTEXT" \
  --encoding base64 \
  --key-hex "AES_KEY_HEX" \
  --iv-hex "16_BYTE_IV_HEX"
```

If the protocol provides a separate HMAC tag:

```bash
python c2_crypto_helper.py aes-cbc \
  --input-file encrypted-field.bin \
  --encoding raw \
  --key-hex "AES_KEY_HEX" \
  --iv-hex "16_BYTE_IV_HEX" \
  --hmac-key-hex "HMAC_KEY_HEX" \
  --hmac-tag-hex "EXPECTED_TAG_HEX" \
  --hmac-algorithm sha256 \
  --hmac-input iv-ciphertext
```

HMAC verification happens before decryption. A failed tag stops the operation. Use the correct authentication coverage and tag length from the confirmed protocol layout.

## RSA decryption tool

OAEP with SHA-256:

```bash
python c2_crypto_helper.py rsa \
  --value "PASTE_BASE64_CIPHERTEXT" \
  --encoding base64 \
  --private-key analysis-private.pem \
  --padding oaep-sha256
```

Legacy PKCS#1 v1.5 is available only for protocols or labs that explicitly require it:

```bash
python c2_crypto_helper.py rsa \
  --input-file metadata.bin \
  --encoding raw \
  --private-key analysis-private.pem \
  --padding pkcs1v15
```

For an encrypted PEM, place the password in an environment variable rather than command history:

```bash
export C2_KEY_PASSWORD='temporary-lab-password'
python c2_crypto_helper.py rsa \
  --input-file metadata.bin \
  --encoding raw \
  --private-key analysis-private.pem \
  --key-password-env C2_KEY_PASSWORD
```

## Correct decryption workflow

1. Identify the suspected host, destination, stream, direction, and timestamp.
2. Select only the exact cookie, URI value, body, or binary field needed.
3. Reverse confirmed transforms such as URL encoding, Base64URL, or hex.
4. Confirm the framework or protocol layout.
5. Record the key source, algorithm, mode, IV or nonce, authentication coverage, tag placement, and padding.
6. Verify authentication before decryption when the protocol uses a MAC or tag.
7. Decrypt offline and review only a bounded preview.
8. Record limitations honestly; failed decryption does not prove benign traffic.

Different C2 frameworks do not share one encryption format. Framework adapters should remain separate modules and should be added only after their packet layout, transforms, key derivation, and version behaviour are documented and tested.

## Tests

```bash
python -m pip install ".[dev]"
python -m pytest -q
```

Tests use synthetic packets, keys, and ciphertext. They do not download malware, contact external systems, or execute captured content.

## Analyst judgement rule

Do not decide from one indicator or one successful decode. Combine timing, endpoints, DNS, HTTP or TLS metadata, endpoint telemetry, identity, threat intelligence, decrypted evidence, scope, user impact, and business context before assigning a verdict.
