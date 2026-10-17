"""Generate a deterministic CSV file for practicing with the detector."""

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path


def create_sample_rows() -> list[dict[str, str]]:
    """Build ordinary traffic plus three distinct port-scan scenarios."""
    start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    rows: list[dict[str, str]] = []

    def add_event(
        seconds: int, src_ip: str, dst_ip: str, dst_port: int, flags: str
    ) -> None:
        timestamp = start + timedelta(seconds=seconds)
        rows.append(
            {
                "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": str(dst_port),
                "flags": flags,
            }
        )

    # Ordinary connections: each source contacts only a few services.
    for index in range(10):
        source_number = index % 3 + 10
        destination_number = index % 4 + 20
        add_event(
            seconds=index * 3,
            src_ip=f"192.0.2.{source_number}",
            dst_ip=f"198.51.100.{destination_number}",
            dst_port=[22, 53, 80, 443][index % 4],
            flags="SYN",
        )

        add_event(
            seconds=index * 3 + 1,
            src_ip=f"192.0.2.{source_number}",
            dst_ip=f"198.51.100.{destination_number}",
            dst_port=[22, 53, 80, 443][index % 4],
            flags="ACK",
        )

    # Vertical scan: one source probes many ports on one destination.
    for index, port in enumerate(range(20, 42)):
        add_event(40 + index * 2, "203.0.113.10", "198.51.100.10", port, "SYN")

    # Horizontal scan: one source probes the same port on many destinations.
    for index in range(22):
        add_event(
            100 + index * 2,
            "203.0.113.20",
            f"198.51.100.{index + 30}",
            445,
            "SYN",
        )

    # SYN-only activity: repeated SYN packets with no matching ACK events.
    for index in range(22):
        add_event(160 + index * 2, "203.0.113.30", "198.51.100.60", 443, "SYN")

    # A later observed TCP event lets the final SYN attempts reach their deadline.
    add_event(208, "192.0.2.10", "198.51.100.20", 443, "ACK")
    return sorted(rows, key=lambda row: row["timestamp"])


def write_samples(output_path: Path) -> None:
    """Write generated sample rows to output_path as a CSV file."""
    fields = ["timestamp", "src_ip", "dst_ip", "dst_port", "flags"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(create_sample_rows())


if __name__ == "__main__":
    sample_path = Path(__file__).with_name("events.csv")
    write_samples(sample_path)
    print(f"Wrote sample events to {sample_path}")
