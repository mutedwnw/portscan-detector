"""Command-line interface for the port scan detector."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from detector.parser import parse_csv, parse_pcap
from detector.report import print_alert_table, write_reports
from detector.rules import detect_scans


@dataclass(frozen=True)
class DetectorConfig:
    """Validated settings needed by the detection rules."""

    window_seconds: int
    vertical_unique_ports: int
    horizontal_unique_hosts: int
    syn_without_ack: int


def _positive_integer(value: object, setting_name: str) -> int:
    """Return a positive integer config value or explain the problem."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"'{setting_name}' must be a positive integer")
    return value


def load_config(path: Path) -> DetectorConfig:
    """Load and validate the YAML configuration file."""
    with path.open("r", encoding="utf-8") as config_file:
        raw_config = yaml.safe_load(config_file)

    if not isinstance(raw_config, dict):
        raise ValueError("configuration must be a YAML mapping")

    raw_thresholds = raw_config.get("thresholds", {})
    if not isinstance(raw_thresholds, dict):
        raise ValueError("'thresholds' must be a YAML mapping")

    return DetectorConfig(
        window_seconds=_positive_integer(
            raw_config.get("window_seconds", 60), "window_seconds"
        ),
        vertical_unique_ports=_positive_integer(
            raw_thresholds.get("vertical_unique_ports", 20),
            "thresholds.vertical_unique_ports",
        ),
        horizontal_unique_hosts=_positive_integer(
            raw_thresholds.get("horizontal_unique_hosts", 20),
            "thresholds.horizontal_unique_hosts",
        ),
        syn_without_ack=_positive_integer(
            raw_thresholds.get("syn_without_ack", 20),
            "thresholds.syn_without_ack",
        ),
    )


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the command-line interface."""
    argument_parser = argparse.ArgumentParser(
        description="Detect port-scanning patterns in a network CSV log."
    )
    argument_parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="path to the input CSV, PCAP, or PCAPNG file",
    )
    argument_parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.yaml"),
        help="path to the YAML configuration file (default: config.yaml)",
    )
    argument_parser.add_argument(
        "--output",
        type=Path,
        help="optional output base path; JSON and CSV files will be created",
    )
    return argument_parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run detection, and show or save the results."""
    argument_parser = build_argument_parser()
    args = argument_parser.parse_args(argv)

    try:
        config = load_config(args.config)
        if args.input.suffix.lower() in {".pcap", ".pcapng"}:
            events = parse_pcap(args.input)
        else:
            events = parse_csv(args.input)
        alerts = detect_scans(
            events,
            window_seconds=config.window_seconds,
            vertical_threshold=config.vertical_unique_ports,
            horizontal_threshold=config.horizontal_unique_hosts,
            syn_threshold=config.syn_without_ack,
        )
        print_alert_table(alerts)
        if args.output is not None:
            json_path, csv_path = write_reports(alerts, args.output)
            print(f"Saved JSON report to {json_path}")
            print(f"Saved CSV report to {csv_path}")
    except (OSError, RuntimeError, ValueError, yaml.YAMLError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
