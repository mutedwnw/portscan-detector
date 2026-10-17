"""Console, JSON, and CSV report formatting."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from detector.rules import Alert


def _alert_to_dict(alert: Alert) -> dict[str, str | int]:
    """Convert an alert into values that JSON and CSV can serialize."""
    alert_data = asdict(alert)
    alert_data["first_seen"] = alert.first_seen.isoformat()
    alert_data["last_seen"] = alert.last_seen.isoformat()
    return alert_data


def format_alert_table(alerts: list[Alert]) -> str:
    """Return alerts as a readable fixed-width console table."""
    if not alerts:
        return "No scan alerts found."

    columns = [
        ("Rule", "rule"),
        ("Source IP", "src_ip"),
        ("Target", "target"),
        ("Count", "event_count"),
        ("First seen", "first_seen"),
        ("Last seen", "last_seen"),
        ("MITRE", "mitre"),
    ]
    rows = [_alert_to_dict(alert) for alert in alerts]
    widths = [
        max(len(title), *(len(str(row[key])) for row in rows))
        for title, key in columns
    ]

    header = " | ".join(title.ljust(width) for (title, _), width in zip(columns, widths))
    divider = "-+-".join("-" * width for width in widths)
    body = [
        " | ".join(str(row[key]).ljust(width) for (_, key), width in zip(columns, widths))
        for row in rows
    ]
    return "\n".join([header, divider, *body])


def print_alert_table(alerts: list[Alert]) -> None:
    """Print the formatted alert table to the console."""
    print(format_alert_table(alerts))


def write_reports(
    alerts: list[Alert], output_base: Path, *, protected_paths: tuple[Path, ...] = ()
) -> tuple[Path, Path]:
    """Write JSON and CSV reports using output_base as their shared name.

    If output_base ends in .json or .csv, that suffix is removed before both
    report filenames are formed. For example, alerts.json creates alerts.json
    and alerts.csv.
    """
    if output_base.suffix.lower() in {".json", ".csv"}:
        output_base = output_base.with_suffix("")

    json_path = Path(str(output_base) + ".json")
    csv_path = Path(str(output_base) + ".csv")
    outputs = (json_path, csv_path)
    for output in outputs:
        for protected in protected_paths:
            if output.resolve() == protected.resolve() or (
                output.exists() and protected.exists() and output.samefile(protected)
            ):
                raise ValueError(f"report path would overwrite input or configuration: {output}")
    if json_path.exists() and csv_path.exists() and json_path.samefile(csv_path):
        raise ValueError("JSON and CSV output paths refer to the same file")
    json_path.parent.mkdir(parents=True, exist_ok=True)

    rows = [_alert_to_dict(alert) for alert in alerts]
    with json_path.open("w", encoding="utf-8") as json_file:
        json.dump(rows, json_file, ensure_ascii=False, indent=2)
        json_file.write("\n")

    fieldnames = list(rows[0]) if rows else [
        "rule",
        "src_ip",
        "target",
        "first_seen",
        "last_seen",
        "event_count",
        "description",
        "mitre",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    return json_path, csv_path
