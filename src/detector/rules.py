"""Sliding-window rules for detecting port-scanning behavior."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from detector.parser import Event


@dataclass(frozen=True)
class Alert:
    """A detection produced by one of the scan rules."""

    rule: str
    src_ip: str
    target: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    description: str
    mitre: str = "T1046"


def _has_flag(flags: str, wanted_flag: str) -> bool:
    """Check a comma- or space-separated flag field for one flag token."""
    flag_tokens = flags.replace(",", " ").split()
    return wanted_flag in flag_tokens


def _remove_expired(
    events: deque[Event], current_time: datetime, window: timedelta
) -> None:
    """Discard events older than the window ending at current_time."""
    while events and current_time - events[0].timestamp > window:
        events.popleft()


def _detect_vertical(
    events: list[Event], window: timedelta, threshold: int
) -> list[Alert]:
    """Find one source probing many ports on the same destination."""
    windows: dict[tuple[str, str], deque[Event]] = {}
    alerted_groups: set[tuple[str, str]] = set()
    alerts: list[Alert] = []

    for event in events:
        key = (event.src_ip, event.dst_ip)
        current = windows.setdefault(key, deque())
        _remove_expired(current, event.timestamp, window)
        if not current:
            alerted_groups.discard(key)
        current.append(event)

        unique_ports = {item.dst_port for item in current}
        if len(unique_ports) >= threshold and key not in alerted_groups:
            alerts.append(
                Alert(
                    rule="vertical_scan",
                    src_ip=event.src_ip,
                    target=event.dst_ip,
                    first_seen=current[0].timestamp,
                    last_seen=event.timestamp,
                    event_count=len(unique_ports),
                    description=(
                        f"{len(unique_ports)} unique destination ports on "
                        f"{event.dst_ip} within the time window"
                    ),
                )
            )
            alerted_groups.add(key)

    return alerts


def _detect_horizontal(
    events: list[Event], window: timedelta, threshold: int
) -> list[Alert]:
    """Find one source probing many destinations on the same port."""
    windows: dict[tuple[str, int], deque[Event]] = {}
    alerted_groups: set[tuple[str, int]] = set()
    alerts: list[Alert] = []

    for event in events:
        key = (event.src_ip, event.dst_port)
        current = windows.setdefault(key, deque())
        _remove_expired(current, event.timestamp, window)
        if not current:
            alerted_groups.discard(key)
        current.append(event)

        unique_hosts = {item.dst_ip for item in current}
        if len(unique_hosts) >= threshold and key not in alerted_groups:
            alerts.append(
                Alert(
                    rule="horizontal_scan",
                    src_ip=event.src_ip,
                    target=f"destination port {event.dst_port}",
                    first_seen=current[0].timestamp,
                    last_seen=event.timestamp,
                    event_count=len(unique_hosts),
                    description=(
                        f"Destination port {event.dst_port} on "
                        f"{len(unique_hosts)} hosts within the time window"
                    ),
                )
            )
            alerted_groups.add(key)

    return alerts


def _detect_syn_only(
    events: list[Event], window: timedelta, threshold: int
) -> list[Alert]:
    """Find many SYNs from a source that have no later matching ACK event."""
    windows: dict[str, deque[Event]] = {}
    alerted_sources: set[str] = set()
    alerts: list[Alert] = []

    for event in events:
        current = windows.setdefault(event.src_ip, deque())
        _remove_expired(current, event.timestamp, window)
        if not current:
            alerted_sources.discard(event.src_ip)

        if _has_flag(event.flags, "ACK"):
            current = deque(
                pending
                for pending in current
                if not (
                    pending.dst_ip == event.dst_ip
                    and pending.dst_port == event.dst_port
                    and (
                        pending.src_port is None
                        or event.src_port is None
                        or pending.src_port == event.src_port
                    )
                    and pending.timestamp < event.timestamp
                )
            )
            windows[event.src_ip] = current
            if not current:
                alerted_sources.discard(event.src_ip)

        if _has_flag(event.flags, "SYN") and not _has_flag(event.flags, "ACK"):
            current.append(event)

        if len(current) >= threshold and event.src_ip not in alerted_sources:
            alerts.append(
                Alert(
                    rule="syn_without_ack",
                    src_ip=event.src_ip,
                    target="multiple destinations or ports",
                    first_seen=current[0].timestamp,
                    last_seen=event.timestamp,
                    event_count=len(current),
                    description=(
                        f"{len(current)} SYN events without a later matching "
                        "ACK in the time window"
                    ),
                )
            )
            alerted_sources.add(event.src_ip)

    return alerts


def detect_scans(
    events: list[Event],
    *,
    window_seconds: int = 60,
    vertical_threshold: int = 20,
    horizontal_threshold: int = 20,
    syn_threshold: int = 20,
) -> list[Alert]:
    """Run all scan rules and return alerts in detection-time order.

    Events are sorted by timestamp before analysis. Each rule keeps a rolling
    window: before adding the current event, it removes events older than the
    configured duration.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")
    if min(vertical_threshold, horizontal_threshold, syn_threshold) <= 0:
        raise ValueError("all detection thresholds must be greater than zero")

    ordered_events = sorted(events, key=lambda item: item.timestamp)
    window = timedelta(seconds=window_seconds)

    alerts = [
        *_detect_vertical(ordered_events, window, vertical_threshold),
        *_detect_horizontal(ordered_events, window, horizontal_threshold),
        *_detect_syn_only(ordered_events, window, syn_threshold),
    ]
    return sorted(alerts, key=lambda item: item.last_seen)
