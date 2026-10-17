"""Tests for CSV parsing and the scan detection rules."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from detector.parser import Event, parse_csv
from detector.rules import detect_scans


def make_event(
    seconds: int,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    flags: str = "SYN",
    src_port: int = 50000,
) -> Event:
    """Create a timestamped event for a rule test."""
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
        seconds=seconds
    )
    return Event(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        flags=flags,
        src_port=src_port,
    )


def test_normal_traffic_does_not_raise_alerts() -> None:
    """A few completed connections should stay below every threshold."""
    events: list[Event] = []
    for index, port in enumerate([22, 80, 443]):
        destination = f"198.51.100.{index + 1}"
        source_port = 50000 + index
        events.append(
            make_event(index * 3, "192.0.2.10", destination, port, "SYN", source_port)
        )
        events.append(
            make_event(
                index * 3 + 1,
                "192.0.2.10",
                destination,
                port,
                "ACK",
                source_port,
            )
        )

    assert detect_scans(events) == []


def test_vertical_scan_is_detected() -> None:
    """Many unique ports on one destination trigger the vertical rule."""
    events = [
        make_event(
            seconds=port,
            src_ip="203.0.113.10",
            dst_ip="198.51.100.10",
            dst_port=port,
        )
        for port in range(1, 21)
    ]

    alerts = detect_scans(events)

    assert any(alert.rule == "vertical_scan" for alert in alerts)


def test_horizontal_scan_is_detected() -> None:
    """One source probing the same port on many hosts triggers the rule."""
    events = [
        make_event(
            seconds=index,
            src_ip="203.0.113.20",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=445,
        )
        for index in range(20)
    ]

    alerts = detect_scans(events)

    assert any(alert.rule == "horizontal_scan" for alert in alerts)


def test_syn_without_ack_is_detected() -> None:
    """Repeated SYNs without later ACKs trigger the SYN rule."""
    events = [
        make_event(
            seconds=index,
            src_ip="203.0.113.30",
            dst_ip="198.51.100.60",
            dst_port=443,
        )
        for index in range(20)
    ]

    events.append(make_event(25, "192.0.2.99", "198.51.100.99", 443, "ACK"))
    alerts = detect_scans(events)

    assert any(alert.rule == "syn_without_ack" for alert in alerts)


def test_malformed_csv_row_is_skipped(tmp_path: Path) -> None:
    """A bad row warns but does not stop parsing later valid rows."""
    csv_path = tmp_path / "events.csv"
    csv_path.write_text(
        "timestamp,src_ip,dst_ip,dst_port,flags\n"
        "2026-01-01T12:00:00Z,192.0.2.10,198.51.100.10,443,SYN\n"
        "not-a-time,not-an-ip,198.51.100.10,wrong,SYN\n"
        "2026-01-01T12:00:02Z,192.0.2.11,198.51.100.11,80,ACK\n",
        encoding="utf-8",
    )

    with pytest.warns(RuntimeWarning, match="Skipping malformed CSV row 3"):
        events = parse_csv(csv_path)

    assert len(events) == 2
