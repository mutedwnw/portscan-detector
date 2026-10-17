"""Offline TCP scan detection with bounded sliding-window state."""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Callable, Hashable
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import groupby

from detector.parser import Event


@dataclass(frozen=True)
class Alert:
    """A threshold crossing; count and times describe its triggering window."""

    rule: str
    src_ip: str
    target: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    description: str
    mitre: str = "T1046"


def _has_flag(flags: str, wanted_flag: str) -> bool:
    """Check a comma- or space-separated flag field for one token."""
    return wanted_flag in flags.upper().replace(",", " ").split()


def _is_probe(event: Event) -> bool:
    """Only an initial SYN represents a new TCP connection attempt."""
    return _has_flag(event.flags, "SYN") and not _has_flag(event.flags, "ACK")


def _detect_window(
    events: list[Event],
    window: timedelta,
    threshold: int,
    rule: str,
    group_key: Callable[[Event], Hashable],
    value_key: Callable[[Event], Hashable] | None,
    target: Callable[[Event], str],
    unit: str,
) -> list[Alert]:
    """Count values incrementally; expire all groups and rearm below threshold."""
    timeline: deque[Event] = deque()
    groups: dict[Hashable, deque[Event]] = {}
    counts: dict[Hashable, Counter[Hashable]] = {}
    alerted: set[Hashable] = set()
    alerts: list[Alert] = []

    def count(key: Hashable) -> int:
        return len(counts[key]) if value_key else len(groups[key])

    for event in events:
        # Global expiration also clears groups that never send another event.
        while timeline and event.timestamp - timeline[0].timestamp > window:
            expired = timeline.popleft()
            key = group_key(expired)
            groups[key].popleft()
            if value_key:
                value = value_key(expired)
                counts[key][value] -= 1
                if counts[key][value] == 0:
                    del counts[key][value]
            if count(key) < threshold:
                alerted.discard(key)
            if not groups[key]:
                del groups[key]
                del counts[key]

        key = group_key(event)
        groups.setdefault(key, deque()).append(event)
        counts.setdefault(key, Counter())
        timeline.append(event)
        if value_key:
            counts[key][value_key(event)] += 1
        total = count(key)
        if total >= threshold and key not in alerted:
            alerts.append(Alert(
                rule=rule,
                src_ip=event.src_ip,
                target=target(event),
                first_seen=groups[key][0].timestamp,
                last_seen=event.timestamp,
                event_count=total,
                description=f"{total} {unit} in the triggering time window",
            ))
            alerted.add(key)
    return alerts


def _unacknowledged_syns(events: list[Event], timeout: timedelta) -> list[Event]:
    """Return SYNs whose ACK deadline passed during the observed TCP timeline.

    ACKs at the deadline are accepted. Events sharing a timestamp are treated
    as simultaneous, allowing logs with coarse timestamp resolution. Pending
    SYNs at the end of the recording are not assumed to have timed out.
    """
    pending: dict[tuple[str, str, int, int | None], dict[int, Event]] = {}
    deadlines: deque[tuple[int, Event]] = deque()
    expired: list[Event] = []
    serial = 0

    def flow(event: Event) -> tuple[str, str, int, int | None]:
        return event.src_ip, event.dst_ip, event.dst_port, event.src_port

    def expire(now: datetime, inclusive: bool) -> None:
        while deadlines:
            number, event = deadlines[0]
            age = now - event.timestamp
            if age < timeout or (age == timeout and not inclusive):
                break
            deadlines.popleft()
            key = flow(event)
            attempts = pending.get(key)
            if attempts is not None and number in attempts:
                expired.append(attempts.pop(number))
                if not attempts:
                    del pending[key]

    for timestamp, batch in groupby(events, key=lambda event: event.timestamp):
        expire(timestamp, inclusive=False)
        simultaneous = list(batch)
        for event in simultaneous:
            if _is_probe(event):
                serial += 1
                pending.setdefault(flow(event), {})[serial] = event
                deadlines.append((serial, event))
        for event in simultaneous:
            if _has_flag(event.flags, "ACK"):
                pending.pop(flow(event), None)
        expire(timestamp, inclusive=True)
    return expired


def detect_scans(
    events: list[Event],
    *,
    window_seconds: int = 60,
    vertical_threshold: int = 20,
    horizontal_threshold: int = 20,
    syn_threshold: int = 20,
    syn_ack_timeout_seconds: int = 5,
) -> list[Alert]:
    """Analyze sorted TCP events; report one alert per threshold crossing.

    Windows include both endpoints. SYN timeouts use the last observed TCP
    timestamp, never wall-clock time. Counts are snapshots, not scan totals.
    """
    settings = (window_seconds, vertical_threshold, horizontal_threshold,
                syn_threshold, syn_ack_timeout_seconds)
    if any(type(value) is not int or value <= 0 for value in settings):
        raise ValueError("windows, timeouts and thresholds must be positive integers")
    try:
        window = timedelta(seconds=window_seconds)
        timeout = timedelta(seconds=syn_ack_timeout_seconds)
    except OverflowError as error:
        raise ValueError("window or timeout is too large") from error
    ordered = sorted(events, key=lambda event: event.timestamp)
    probes = [event for event in ordered if _is_probe(event)]
    alerts = _detect_window(
        probes, window, vertical_threshold, "vertical_scan",
        lambda event: (event.src_ip, event.dst_ip), lambda event: event.dst_port,
        lambda event: event.dst_ip, "unique destination ports",
    )
    alerts += _detect_window(
        probes, window, horizontal_threshold, "horizontal_scan",
        lambda event: (event.src_ip, event.dst_port), lambda event: event.dst_ip,
        lambda event: f"destination port {event.dst_port}", "unique destinations",
    )
    alerts += _detect_window(
        _unacknowledged_syns(ordered, timeout), window, syn_threshold,
        "syn_without_ack", lambda event: event.src_ip, None,
        lambda event: "multiple destinations or ports",
        f"SYN events without ACK within {syn_ack_timeout_seconds} seconds",
    )
    return sorted(alerts, key=lambda alert: alert.last_seen)
