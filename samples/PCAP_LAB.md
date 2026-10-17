# PCAP lab: compare Nmap `-sS` and `-sT`

Only scan a virtual machine that you own or have explicit permission to test.
Use the private or host-only network between your own lab VMs.

## 1. Install optional Scapy support

Activate the project's virtual environment, then run:

```bash
python -m pip install scapy==2.8.0
```

Scapy is optional. CSV input continues to work without it.

## 2. Find the capture interface and target address

On macOS or Linux, list capture interfaces with:

```bash
sudo tcpdump -D
```

Find the target VM's private IP address from that VM's network settings. Use the
interface connected to the lab network in place of `<interface>` below.

## 3. Capture a SYN scan

In terminal 1, start capturing packets to the target VM:

```bash
sudo tcpdump -i <interface> -nn -w samples/nmap-sS.pcap "host <target-ip> and tcp"
```

In terminal 2, scan that same VM:

```bash
sudo nmap -sS -n -p 1-100 <target-ip>
```

After Nmap finishes, keep observing for longer than `syn_ack_timeout_seconds`
(default 5 seconds). Generate a normal connection to a known service on your
own target VM after that delay, so the recording contains a later TCP event.
Then return to terminal 1 and press `Ctrl+C` to close the capture. Waiting alone
without any later TCP traffic does not advance this detector's observation end.

## 4. Capture a TCP connect scan

Repeat the capture with a different filename:

```bash
sudo tcpdump -i <interface> -nn -w samples/nmap-sT.pcap "host <target-ip> and tcp"
```

Then, in terminal 2, run:

```bash
nmap -sT -n -p 1-100 <target-ip>
```

Use the same observation-tail procedure as above, then stop with `Ctrl+C`.

## 5. Analyze both captures

From the project directory, run:

```bash
PYTHONPATH=src python -m detector.cli --input samples/nmap-sS.pcap --config config.yaml --output reports/nmap-sS
PYTHONPATH=src python -m detector.cli --input samples/nmap-sT.pcap --config config.yaml --output reports/nmap-sT
```

Each run prints a table and saves JSON and CSV reports under `reports/`.

## What to expect

Nmap's `-sS` sends SYN probes without completing TCP connections. `-sT` asks the
operating system to establish connections to open ports. The detector uses the
available packet fields to look for SYN events without a later ACK in the same
direction and flow. The CSV format has no source port, so ACK matching is only
an approximation for CSV. PCAP events include the source port and allow a more
specific match. Closed or filtered ports, packet loss, retransmissions, and the
configured threshold can still affect the alerts; compare the packet captures
and reports rather than treating the result as proof by itself.


## Interpretation

Only initial SYN packets contribute to vertical/horizontal scans; replies to
client ephemeral ports do not make the server a scanner. The SYN rule waits
for the configured ACK timeout and ignores attempts too close to the last TCP
event to evaluate. ACKs at the exact deadline are accepted; later ACKs do not
undo a timeout. `-sT` against closed or filtered ports can still produce SYN
alerts, and `-sS` is not the only cause of incomplete handshakes. Neither an
alert nor its absence reliably identifies the Nmap mode. Use the captures to
explain what actually happened.
