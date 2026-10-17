"""Regression tests for real traffic, malformed inputs and safe reporting."""

import builtins
import csv
import json
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from detector.cli import load_config, main
from detector.parser import Event, parse_csv, parse_pcap
from detector.report import format_alert_table, write_reports
from detector.rules import detect_scans


def event(t, port=443, flags="SYN", src="192.0.2.1", dst="198.51.100.1", sport=50000):
    return Event(datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=t),
                 src, dst, port, flags, sport)


def end(t):
    return event(t, flags="ACK", src="192.0.2.99")


def csv_file(tmp_path, rows):
    path = tmp_path / "events.csv"
    path.write_text("timestamp,src_ip,dst_ip,dst_port,flags\n" + rows, encoding="utf-8")
    return path


def config_file(tmp_path, text="{}"):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_concurrent_completed_connections_are_not_scans():
    events = [event(i / 1000, sport=50000+i) for i in range(30)]
    events += [event(1+i / 1000, flags="ACK", sport=50000+i) for i in range(30)]
    assert detect_scans(events + [end(10)]) == []


def test_server_responses_do_not_make_server_a_scanner():
    events = []
    for i in range(30):
        events += [event(i, sport=50000+i),
                   event(i+.1, 50000+i, "SYN,ACK", "198.51.100.1", "192.0.2.1", 443),
                   event(i+.2, flags="ACK", sport=50000+i)]
    assert detect_scans(events + [end(40)]) == []


@pytest.mark.parametrize("rule", ["vertical_scan", "horizontal_scan", "syn_without_ack"])
def test_repeated_scan_after_count_drops_below_threshold(rule):
    def probe(t, i):
        if rule == "vertical_scan":
            return event(t, port=1000+i)
        if rule == "horizontal_scan":
            return event(t, dst=f"198.51.100.{i+1}")
        return event(t)
    events = [probe(i, i) for i in range(20)]
    events += [probe(t, 0) for t in (50, 80, 110)]
    events += [probe(120+i, i) for i in range(20)]
    alerts = [a for a in detect_scans(events + [end(150)]) if a.rule == rule]
    assert len(alerts) == 2


@pytest.mark.parametrize("ack_time,expected", [(4, 0), (5, 0), (6, 1)])
def test_ack_deadline(ack_time, expected):
    events = [event(0), event(ack_time, flags="ACK"), end(10)]
    alerts = detect_scans(events, syn_threshold=1)
    assert len([a for a in alerts if a.rule == "syn_without_ack"]) == expected


def test_syns_at_end_of_capture_are_not_assumed_timed_out():
    assert detect_scans([event(0, sport=50000+i) for i in range(20)]) == []


def test_ack_with_same_timestamp_is_matched_even_if_input_order_is_reversed():
    assert detect_scans([event(0, flags="ACK"), event(0), end(10)], syn_threshold=1) == []


def test_ack_on_other_flow_does_not_clear_syn():
    alerts = detect_scans([event(0), event(1, flags="ACK", sport=50001), end(10)], syn_threshold=1)
    assert [a.rule for a in alerts] == ["syn_without_ack"]


def test_server_ack_does_not_complete_client_handshake():
    events = [event(0), event(1, 50000, "SYN,ACK", "198.51.100.1", "192.0.2.1", 443), end(10)]
    assert [a.rule for a in detect_scans(events, syn_threshold=1)] == ["syn_without_ack"]


@pytest.mark.parametrize("gap,expected", [(60, 1), (60.001, 0)])
def test_window_includes_exact_boundary(gap, expected):
    alerts = detect_scans([event(0, port=80), event(gap, port=443)], vertical_threshold=2)
    assert len([a for a in alerts if a.rule == "vertical_scan"]) == expected


def test_unsorted_events_and_duplicate_ports():
    probes = [event(i, port=1000+i) for i in range(20)]
    assert detect_scans(probes) == detect_scans(list(reversed(probes)))
    assert not any(a.rule == "vertical_scan" for a in detect_scans([event(i) for i in range(30)]))


def test_count_is_threshold_snapshot_not_scan_total():
    alerts = detect_scans([event(i/10, port=1000+i) for i in range(100)])
    vertical = [a for a in alerts if a.rule == "vertical_scan"]
    assert len(vertical) == 1 and vertical[0].event_count == 20


@pytest.mark.parametrize("row", [
    '2026-01-01T00:00:00Z,192.0.2.1,198.51.100.1,443,SYN,ACK\n',
    '2026-01-01T00:00:00Z,192.0.2.1,198.51.100.1,443,INVALID\n',
    '2026-01-01T00:00:00Z,192.0.2.1,198.51.100.1,443\n',
    '2026-01-01T00:00:00Z,192.0.2.1,198.51.100.1,443,"NONE,SYN"\n',
])
def test_bad_rows_are_skipped_and_later_rows_survive(tmp_path, row):
    path = csv_file(tmp_path, row+'2026-01-01T00:00:01Z,192.0.2.1,198.51.100.1,443,ACK\n')
    with pytest.warns(RuntimeWarning):
        events = parse_csv(path)
    assert len(events) == 1 and events[0].flags == "ACK"


def test_quoted_flags_and_ipv6_normalization(tmp_path):
    path = csv_file(tmp_path, '2026-01-01T00:00:00Z,2001:0db8::2,2001:0db8::1,443,"SYN,ACK"\n')
    parsed = parse_csv(path)[0]
    assert parsed.flags == "SYN,ACK"
    assert parsed.src_ip == "2001:db8::2" and parsed.dst_ip == "2001:db8::1"


def test_ipv6_spellings_group_as_one_destination(tmp_path):
    rows = ''.join(f'2026-01-01T00:00:{i:02d}Z,2001:db8::2,{"2001:0db8::1" if i%2 else "2001:db8::1"},{1000+i},SYN\n' for i in range(20))
    assert any(a.rule == "vertical_scan" for a in detect_scans(parse_csv(csv_file(tmp_path, rows))))


@pytest.mark.parametrize("flags", ['X' * 140000, '"SYN'])
def test_structurally_broken_csv_returns_cli_error(tmp_path, capsys, flags):
    path = csv_file(tmp_path, '2026-01-01T00:00:00Z,192.0.2.1,198.51.100.1,443,'+flags+'\n')
    config = config_file(tmp_path)
    assert main(['--input', str(path), '--config', str(config)]) == 2
    assert "analysis incomplete" in capsys.readouterr().err


def test_duplicate_header_is_rejected(tmp_path):
    path = tmp_path/'bad.csv'
    path.write_text('timestamp,src_ip,dst_ip,dst_port,flags,flags\n')
    with pytest.raises(ValueError, match='duplicate'):
        parse_csv(path)


@pytest.mark.parametrize("name,expected", [('alerts.run1', 'alerts.run1'), ('alerts.run1.json', 'alerts.run1'), ('alerts.run1.CSV', 'alerts.run1')])
def test_report_names_keep_dots(tmp_path, name, expected):
    jp, cp = write_reports([], tmp_path/name)
    assert jp.name == expected+'.json' and cp.name == expected+'.csv'
    assert json.loads(jp.read_text()) == []
    assert list(csv.DictReader(cp.open())) == []


def test_cli_does_not_overwrite_input(tmp_path, capsys):
    path = csv_file(tmp_path, '2026-01-01T00:00:00Z,192.0.2.1,198.51.100.1,443,SYN\n')
    before = path.read_bytes()
    config = config_file(tmp_path)
    assert main(['--input', str(path), '--config', str(config), '--output', str(tmp_path/'events.json')]) == 2
    assert path.read_bytes() == before
    assert not (tmp_path/'events.json').exists()
    assert 'overwrite' in capsys.readouterr().err


@pytest.mark.parametrize("link", ['symlink', 'hardlink'])
def test_output_alias_of_protected_file_is_rejected(tmp_path, link):
    protected = tmp_path/'config.yaml'; protected.write_text('{}')
    alias = tmp_path/'alerts.csv'
    if link == 'symlink': alias.symlink_to(protected)
    else: alias.hardlink_to(protected)
    with pytest.raises(ValueError, match='overwrite'):
        write_reports([], tmp_path/'alerts', protected_paths=(protected,))
    assert protected.read_text() == '{}'
    assert not (tmp_path/'alerts.json').exists()


def test_cli_reports_and_mitre(tmp_path, capsys):
    rows = ''.join(f'2026-01-01T00:00:{i:02d}Z,192.0.2.1,198.51.100.1,{1000+i},SYN\n' for i in range(20))
    path = csv_file(tmp_path, rows); config = config_file(tmp_path)
    base = tmp_path/'nested'/'report'
    assert main(['--input', str(path), '--config', str(config), '--output', str(base)]) == 0
    data = json.loads(base.with_suffix('.json').read_text())
    csv_data = list(csv.DictReader(base.with_suffix('.csv').open()))
    assert len(data) == len(csv_data) == 1
    assert all(row['mitre']=='T1046' for row in data+csv_data)
    assert 'vertical_scan' in capsys.readouterr().out
    assert format_alert_table([]) == 'No scan alerts found.'


@pytest.mark.parametrize('text', ['window_seconds: true', 'window_seconds: 0', 'thresholds: []', '[invalid', 'syn_ack_timeout_seconds: -1', 'window_second: 60'])
def test_invalid_config_is_reported(tmp_path, capsys, text):
    assert main(['--input','missing.csv','--config',str(config_file(tmp_path,text))]) == 2
    assert 'Error:' in capsys.readouterr().err


def test_config_defaults_and_custom_timeout(tmp_path):
    assert load_config(config_file(tmp_path)).syn_ack_timeout_seconds == 5
    assert load_config(config_file(tmp_path,'syn_ack_timeout_seconds: 10')).syn_ack_timeout_seconds == 10


@pytest.mark.parametrize('suffix', ['pcap', 'pcapng'])
@pytest.mark.parametrize('version', [4, 6])
def test_pcap_and_pcapng_eof_and_cli(tmp_path, suffix, version):
    pytest.importorskip('scapy')
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapWriter, PcapNgWriter
    path = tmp_path/f'input.{suffix}'
    packet = (IP(src='192.0.2.1', dst='198.51.100.1') if version==4
              else IPv6(src='2001:db8::1', dst='2001:db8::2'))/TCP(sport=50000, dport=443, flags='S')
    writer_class = PcapWriter if suffix=='pcap' else PcapNgWriter
    with writer_class(str(path)) as writer: writer.write(packet)
    events = parse_pcap(path)
    assert len(events)==1 and events[0].src_port==50000
    assert main(['--input', str(path), '--config', str(config_file(tmp_path))]) == 0


def test_empty_pcap(tmp_path):
    pytest.importorskip('scapy')
    path = tmp_path/'empty.pcap'
    path.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    assert parse_pcap(path)==[]


def test_scapy_is_optional(tmp_path, monkeypatch):
    original_import = builtins.__import__
    def no_scapy(name, *args, **kwargs):
        if name.startswith('scapy'): raise ImportError('not installed')
        return original_import(name,*args,**kwargs)
    monkeypatch.setattr(builtins, '__import__', no_scapy)
    assert parse_csv(csv_file(tmp_path,''))==[]
    with pytest.raises(RuntimeError, match='requires Scapy'):
        parse_pcap(tmp_path/'input.pcap')


@pytest.mark.parametrize('suffix', ['pcap', 'pcapng'])
def test_scan_capture_produces_reports(tmp_path, suffix):
    pytest.importorskip('scapy')
    from scapy.layers.inet import IP, TCP
    from scapy.utils import PcapWriter, PcapNgWriter
    packets = []
    for i in range(20):
        packet = IP(src='192.0.2.1', dst='198.51.100.1')/TCP(sport=50000+i, dport=1000+i, flags='S')
        packet.time = 1767225600+i
        packets.append(packet)
    tail = IP(src='192.0.2.99', dst='198.51.100.1')/TCP(dport=443, flags='A')
    tail.time = 1767225630
    path = tmp_path/f'scan.{suffix}'
    writer_class = PcapWriter if suffix=='pcap' else PcapNgWriter
    with writer_class(str(path)) as writer:
        for packet in packets+[tail]: writer.write(packet)
    base = tmp_path/'scan-report'
    assert main(['--input', str(path), '--config', str(config_file(tmp_path)), '--output', str(base)])==0
    rows=json.loads(base.with_suffix('.json').read_text())
    assert {row['rule'] for row in rows}=={'vertical_scan','syn_without_ack'}


def test_config_cannot_be_overwritten(tmp_path, capsys):
    config=tmp_path/'settings.json'
    config.write_text('{}')  # JSON is a valid YAML mapping.
    source=csv_file(tmp_path,'')
    assert main(['--input',str(source),'--config',str(config),'--output',str(tmp_path/'settings')])==2
    assert config.read_text()=='{}'
    assert not (tmp_path/'settings.csv').exists()


def test_future_timestamp_does_not_overflow_timeout():
    last=Event(datetime.max.replace(tzinfo=timezone.utc),'192.0.2.1','198.51.100.1',443,'SYN')
    assert detect_scans([last],syn_threshold=1)==[]


def test_generated_samples_are_deterministic_and_have_five_alerts(tmp_path):
    import runpy
    namespace=runpy.run_path(str(Path(__file__).parents[1]/'samples'/'generate_samples.py'))
    target=tmp_path/'generated.csv'
    namespace['write_samples'](target)
    checked_in=Path(__file__).parents[1]/'samples'/'events.csv'
    assert target.read_bytes()==checked_in.read_bytes()
    assert len(detect_scans(parse_csv(target)))==5
