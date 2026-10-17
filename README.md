# Port Scan Detector

[Русская версия](README.ru.md)

An educational Python CLI for detecting TCP port-scanning patterns in CSV,
PCAP and PCAPNG files. Alerts are printed as a table and optionally saved as
JSON and CSV. Intended for learning and authorized lab traffic analysis.

Alerts are mapped to MITRE ATT&CK
[T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/).
A match is a signal to investigate, not proof of malicious activity.

## Requirements and installation

Python 3.11 or later is required. From the repository directory on macOS/Linux:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

If `python3` is older than 3.11, use an installed newer interpreter, for example
`python3.11 -m venv .venv`. The editable installation provides the
`portscan-detector` command. `requirements.txt` pins the main dependency and
test runner versions used locally. For optional PCAP support:

```bash
python -m pip install scapy==2.8.0
```

Alternatively, `python -m pip install -e '.[pcap,test]'` installs the project
with both optional dependency groups using the ranges in `pyproject.toml`.

## Run

From the repository directory with the virtual environment active:

```bash
portscan-detector --input samples/events.csv --config config.yaml
portscan-detector --input samples/events.csv --config config.yaml --output reports/alerts
```

The second command creates `reports/alerts.json` and `reports/alerts.csv`.
Both formats are always written. An output ending in `.json` or `.csv` is
interpreted as their shared base name. Other dots are preserved: `alerts.run1`
creates `alerts.run1.json` and `alerts.run1.csv`. Existing reports are replaced;
paths that would overwrite the input or configuration are rejected, including
symbolic links and hard links to those files.

The original module invocation also works without installing the project:

```bash
PYTHONPATH=src python -m detector.cli --input samples/events.csv --config config.yaml
```

`.pcap` and `.pcapng` extensions select Scapy; other extensions select CSV.
Paths are relative to the current working directory. The default configuration
path is `config.yaml`. Exit code `0` means analysis finished, including when
there are alerts; `2` means an input, configuration, or output error.

## Detection rules

Only initial TCP SYN packets (SYN set, ACK absent) count as connection attempts.
Server replies and established-connection traffic do not count as probes.

- **Vertical scan:** one source contacts many unique ports on one destination.
- **Horizontal scan:** one source contacts the same port on many destinations.
- **SYN without ACK:** many SYN events from one source receive no matching ACK
  within `syn_ack_timeout_seconds` (5 seconds by default).

Events are sorted before analysis. Each rule uses an inclusive sliding window:
at time `t`, events in `[t - window_seconds, t]` count. Old events expire from
all active groups; unique-value counters are maintained incrementally. A rule
emits an alert when its count reaches the threshold. It can alert again after
the count falls below the threshold, even when some background traffic remains.

ACK matching uses source IP, destination IP, destination port and, in PCAP,
source port. An ACK at the timeout boundary is accepted. Events with equal
timestamps are treated as simultaneous. CSV lacks source ports, so matching
is approximate. An ACK after the deadline does not undo a timed-out attempt.

Timeouts use timestamps in the file, not the computer's current time. The last
observed TCP event marks the end of observation. SYNs whose deadlines fall after
that point remain inconclusive and do not contribute to the SYN rule. This is
conservative: an idle capture tail without TCP events does not prove elapsed
observation time to this detector.

Rules can overlap. `Count` is a snapshot at the threshold crossing, not the
size of the entire scan: unique ports for vertical, unique hosts for horizontal,
and SYN packets (including retransmissions) for the SYN rule. `first_seen` and
`last_seen` describe original events in that triggering window in UTC, not the
time an ACK timeout was evaluated. Each alert includes `mitre: T1046`.

## Configuration

```yaml
window_seconds: 60
syn_ack_timeout_seconds: 5

thresholds:
  vertical_unique_ports: 20
  horizontal_unique_hosts: 20
  syn_without_ack: 20
```

All values must be positive integers. Missing settings use these defaults;
unknown keys are rejected to catch spelling mistakes. Tune the ACK timeout to
your lab's latency. This detector does not identify the exact Nmap scan mode.

## CSV format

A header and these five columns are required:

```csv
timestamp,src_ip,dst_ip,dst_port,flags
2026-01-01T12:00:00Z,192.0.2.1,198.51.100.1,443,SYN
2026-01-01T12:00:01Z,198.51.100.1,192.0.2.1,50000,"SYN,ACK"
2026-01-01T12:00:02Z,192.0.2.1,198.51.100.1,443,ACK
```

Timestamps require a time zone and are normalized to UTC. IPv4/IPv6 addresses
are validated and normalized. Allowed flag names are `NS`, `CWR`, `ECE`, `URG`,
`ACK`, `PSH`, `RST`, `SYN`, `FIN`, or `NONE` by itself. Names can be separated by
spaces or commas; CSV fields containing commas must be quoted.

Malformed records (invalid values, missing or extra fields) produce a warning
and are skipped. Duplicate or incomplete headers are rejected. Structural
errors, such as an unterminated quoted record or a field exceeding the CSV
reader's limit, stop analysis with a clear error; recovery would require guessing
record boundaries. Files are expected to use UTF-8, with an optional BOM.

## Sample data and output

```bash
python samples/generate_samples.py
portscan-detector --input samples/events.csv --config config.yaml
```

The deterministic sample contains ordinary connections with ACKs and three scan
scenarios. A later TCP event allows the last SYN attempts to reach their
observation deadline. With the default settings, five alerts are expected:

| Rule | Source IP | Target | Count | MITRE |
| --- | --- | --- | --- | --- |
| vertical_scan | 203.0.113.10 | 198.51.100.10 | 20 | T1046 |
| syn_without_ack | 203.0.113.10 | multiple destinations or ports | 20 | T1046 |
| horizontal_scan | 203.0.113.20 | destination port 445 | 20 | T1046 |
| syn_without_ack | 203.0.113.20 | multiple destinations or ports | 20 | T1046 |
| syn_without_ack | 203.0.113.30 | multiple destinations or ports | 20 | T1046 |

This table omits the console's timestamp columns for readability.

## Tests

```bash
python -m pytest -q
```

Regression tests cover completed and concurrent connections, both traffic
directions, ACK deadlines, incomplete observation, repeated scan waves, window
boundaries, malformed CSV, IPv6 normalization, configuration, report paths and
PCAP/PCAPNG reading. PCAP tests skip when Scapy is absent. GitHub Actions is
configured to run tests and a CLI example on Python 3.11–3.15.

## PCAP lab

See [samples/PCAP_LAB.md](samples/PCAP_LAB.md) for capture instructions and a
comparison of `nmap -sS` and `nmap -sT`. Scan only systems you own or have
permission to test.

## Limitations

- Slow scans can stay below the threshold within every window.
- Legitimate high-volume connection attempts can trigger port/host thresholds.
- Lost packets, delayed ACKs, filtered or closed ports and retransmissions can
  trigger the SYN heuristic; a retransmission is counted as another SYN event.
- CSV has no source port. Even PCAP matching does not validate TCP sequence or
  acknowledgement numbers, and reused flows can be ambiguous.
- IPv6 normalization and basic TCP reading are tested. IP fragment reassembly,
  tunnel interpretation and other advanced protocol handling are not implemented.
- Files and sorted event lists are held in memory. Window bookkeeping avoids
  repeated full-window set construction, but this is still an offline tool.
- Counts and timestamps describe threshold crossings, not complete scan episodes.
- Capture damage cannot always be distinguished from EOF by the underlying
  reader. This tool is not a forensic integrity validator.

## Future improvements

- Stream chronologically ordered logs to reduce memory use.
- Deduplicate retransmissions and track TCP sequence numbers.
- Add annotated lab captures and broader IPv6/fragmentation coverage.
- Evaluate threshold choices against larger benign and scan datasets.

## Project structure

```text
portscan-detector/
├── src/detector/
│   ├── __init__.py
│   ├── parser.py
│   ├── rules.py
│   ├── report.py
│   └── cli.py
├── config.yaml
├── samples/
│   ├── events.csv
│   ├── generate_samples.py
│   └── PCAP_LAB.md
├── tests/
│   ├── test_detector.py
│   └── test_regressions.py
├── .github/workflows/tests.yml
├── pyproject.toml
├── requirements.txt
├── README.md
├── README.ru.md
└── .gitignore
```
