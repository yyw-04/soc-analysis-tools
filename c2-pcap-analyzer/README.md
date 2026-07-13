# Defensive C2/PCAP Tools

Modular Python tools for SOC analysts reviewing suspicious PCAP or PCAPNG files and, when exact keys are available, testing selected encrypted C2 fields offline.

> **Safety first:** Treat every capture, key, and decoded value as untrusted evidence. Use an isolated analysis VM or container. The tools never contact observed infrastructure, execute payloads, or automatically extract captured files.

## Choose the correct component

| Component | Purpose | Dependency |
| --- | --- | --- |
| `c2_pcap_analyzer.py` | Passive PCAP/PCAPNG metadata analysis, scan/beacon leads, JSON reporting, and simple decoding | Python standard library only |
| `c2_crypto_helper.py` | Offline RSA or AES-CBC decryption and optional HMAC verification for one analyst-selected field | Optional `cryptography` package |

The crypto helper is not a universal C2 decryptor. It does not recover keys, locate encrypted fields, infer framework profiles, or guess cipher layouts.

## Project structure

```text
c2-pcap-analyzer/
├── c2_pcap_analyzer.py       # Compatibility launcher: passive analyzer
├── c2_crypto_helper.py       # Compatibility launcher: optional crypto helper
├── pyproject.toml            # Core, crypto, and development dependencies
├── soc_c2/
│   ├── analysis.py           # Scan, beacon, and transfer heuristics
│   ├── capture.py            # Bounded PCAP/PCAPNG reader
│   ├── cli.py                # Passive analyzer CLI
│   ├── crypto.py             # Tested RSA, AES-CBC, and HMAC primitives
│   ├── crypto_cli.py         # Offline crypto CLI
│   ├── models.py             # Configuration, models, and safety limits
│   ├── protocols.py          # IP, TCP/UDP, DNS, and HTTP metadata parsing
│   ├── reporting.py          # Human and JSON output
│   ├── transforms.py         # Base64, Base64URL, URL, and hex transforms
│   └── utils.py              # Hashing, timestamps, IP scope, and previews
└── tests/
```

## Safety boundaries

The tools:

- open captures and selected inputs read-only;
- never execute or import captured content;
- never contact IP addresses, domains, or URLs found in evidence;
- never write decrypted plaintext or packet payloads to disk;
- display only a bounded plaintext preview;
- enforce limits on capture, packet, key-file, decoded-input, and preview sizes;
- treat every detection as an investigation lead, not a verdict.

## Installation

Python 3.10 or newer is required.

Passive analyzer only:

```bash
python -m pip install .
```

Analyzer plus RSA/AES/HMAC support:

```bash
python -m pip install ".[crypto]"
```

Development and tests:

```bash
python -m pip install ".[dev]"
```

Dependencies are defined once in `pyproject.toml`:

- core installation: no third-party runtime dependency;
- `crypto` extra: `cryptography`;
- `dev` extra: `pytest` and `cryptography`.

## Passive PCAP analysis

```bash
python c2_pcap_analyzer.py analyze suspicious.pcap
```

Save a structured report:

```bash
python c2_pcap_analyzer.py analyze suspicious.pcap \
  --json-out reports/suspicious-report.json
```

The analyzer records the input SHA-256, time range, endpoints, protocols, destination ports, DNS queries and answers, and clear-text HTTP request metadata. It highlights vertical scans, horizontal scans, periodic communication, and large directional flows for investigation.

### Important analyzer limitations

- Regular timing can also come from updates, telemetry, monitoring, or backups.
- Flow byte counts are capture-observed bytes, not proof of exfiltration.
- Retransmissions, NAT, asymmetric capture, packet loss, and sampling affect results.
- Encrypted application content remains encrypted.
- No detection only lowers suspicion; it does not prove safety.

## Decode a selected representation

Base64, Base64URL, hexadecimal, and URL encoding are transformations, not encryption.

```bash
python c2_pcap_analyzer.py decode --encoding base64 --value "SGVsbG8="
python c2_pcap_analyzer.py decode --encoding hex --value "48656c6c6f"
python c2_pcap_analyzer.py decode --encoding url --value "%48%65%6c%6c%6f"
```

## Offline AES-CBC decryption

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

HMAC verification happens before decryption. A failed tag stops the operation. Do not use `iv-ciphertext`, a truncated tag, or any tag placement unless the protocol layout confirms it.

## Offline RSA decryption

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
2. Extract only the exact cookie, URI value, body, or binary field needed.
3. Reverse confirmed transforms such as URL encoding, Base64URL, or hex.
4. Confirm the framework or protocol layout.
5. Record the key source, algorithm, mode, IV/nonce, authentication coverage, tag placement, and padding.
6. Verify authentication before decryption when the protocol uses a MAC/tag.
7. Decrypt offline and review only a bounded preview.
8. Record limitations honestly; failed decryption does not prove benign traffic.

## Framework-specific support

Different C2 frameworks do not share one encryption format. Framework adapters should be added as separate modules only after their packet layout, transforms, key derivation, and version behaviour are documented and tested. The generic crypto helper supplies primitives; it does not pretend that RSA/AES/HMAC parameters alone describe a complete protocol.

## Tests

```bash
python -m pip install ".[dev]"
python -m pytest -q
python -m py_compile c2_pcap_analyzer.py c2_crypto_helper.py soc_c2/*.py
```

Tests use synthetic packets, keys, and ciphertext. They do not download malware, contact external systems, or execute captured content.

## Analyst judgement rule

Do not decide from one indicator or one successful decode. Combine timing, endpoints, DNS, HTTP/TLS metadata, endpoint telemetry, identity, threat intelligence, decrypted evidence, scope, user impact, and business context before assigning a verdict.
