"""CSV parsing and the event data model used by the detector."""

from __future__ import annotations

import csv
import ipaddress
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Event:
    """One network event parsed from a CSV log row."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    flags: str
    src_port: int | None = None


def _parse_event(row: dict[str, str | None]) -> Event:
    """Convert one CSV row into an Event, validating each required value."""
    timestamp_text = (row.get("timestamp") or "").strip()
    timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must include a timezone, for example +00:00")

    src_ip = (row.get("src_ip") or "").strip()
    dst_ip = (row.get("dst_ip") or "").strip()
    ipaddress.ip_address(src_ip)
    ipaddress.ip_address(dst_ip)

    dst_port = int((row.get("dst_port") or "").strip())
    if not 1 <= dst_port <= 65535:
        raise ValueError("dst_port must be between 1 and 65535")

    flags = (row.get("flags") or "").strip().upper()
    if not flags:
        raise ValueError("flags must not be empty")

    return Event(
        timestamp=timestamp.astimezone(timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        flags=flags,
    )


def parse_csv(path: str | Path) -> list[Event]:
    """Read valid events from CSV and warn about malformed rows.

    Rows with invalid timestamps, addresses, ports, or flags are skipped so a
    single bad record does not prevent the rest of the file from being read.
    File access errors are allowed to reach the caller.
    """
    events: list[Event] = []

    with Path(path).open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        required_columns = {"timestamp", "src_ip", "dst_ip", "dst_port", "flags"}
        header = set(reader.fieldnames or [])
        missing_columns = required_columns - header
        if missing_columns:
            missing_text = ", ".join(sorted(missing_columns))
            raise ValueError(f"CSV is missing required columns: {missing_text}")

        for line_number, row in enumerate(reader, start=2):
            try:
                events.append(_parse_event(row))
            except (AttributeError, TypeError, ValueError) as error:
                warnings.warn(
                    f"Skipping malformed CSV row {line_number}: {error}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    return events


def _tcp_flags_to_names(flag_value: int) -> str:
    """Translate the TCP flag bits from Scapy into readable flag names."""
    flag_names = [
        (0x100, "NS"),
        (0x080, "CWR"),
        (0x040, "ECE"),
        (0x020, "URG"),
        (0x010, "ACK"),
        (0x008, "PSH"),
        (0x004, "RST"),
        (0x002, "SYN"),
        (0x001, "FIN"),
    ]
    names = [name for bit, name in flag_names if flag_value & bit]
    return ",".join(names) if names else "NONE"


def parse_pcap(path: str | Path) -> list[Event]:
    """Read IPv4/IPv6 TCP packets from a pcap file as network events.

    Scapy is imported only when this function is called, so CSV parsing does
    not require the optional Scapy package.
    """
    try:
        from scapy.error import Scapy_Exception
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapReader
    except ImportError as error:
        raise RuntimeError(
            "pcap input requires Scapy; install it with: python -m pip install scapy"
        ) from error

    pcap_path = Path(path)
    try:
        reader = PcapReader(str(pcap_path))
    except (OSError, Scapy_Exception) as error:
        raise ValueError(f"cannot open pcap file '{pcap_path}': {error}") from error

    events: list[Event] = []
    try:
        while True:
            try:
                packet = reader.read_packet()
            except Scapy_Exception as error:
                warnings.warn(
                    f"Stopping at an unreadable pcap packet: {error}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                break

            if packet is None:
                break
            if TCP not in packet:
                continue

            if IP in packet:
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
            elif IPv6 in packet:
                source_ip = packet[IPv6].src
                destination_ip = packet[IPv6].dst
            else:
                continue

            try:
                tcp_layer = packet[TCP]
                events.append(
                    Event(
                        timestamp=datetime.fromtimestamp(
                            float(packet.time), tz=timezone.utc
                        ),
                        src_ip=source_ip,
                        dst_ip=destination_ip,
                        src_port=int(tcp_layer.sport),
                        dst_port=int(tcp_layer.dport),
                        flags=_tcp_flags_to_names(int(tcp_layer.flags)),
                    )
                )
            except (AttributeError, OSError, OverflowError, TypeError, ValueError) as error:
                warnings.warn(
                    f"Skipping an invalid TCP packet: {error}",
                    RuntimeWarning,
                    stacklevel=2,
                )
    finally:
        reader.close()

    return events
