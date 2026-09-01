"""Generate bundled SAMPLE PCAPs with scapy — 100% synthetic, offline.

Nothing is sent over any network: packets are constructed in memory and
written straight to .pcap files. These files let the PCAP-analysis demo
run without downloading anything.

Usage:  python tools/generate_samples.py
"""
from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "pcaps" / "samples"
OUT.mkdir(parents=True, exist_ok=True)

SERVER_MAC = "aa:bb:cc:00:00:01"
CLIENT_MAC = "aa:bb:cc:00:00:02"
OPEN_PORTS = {22, 80, 443}


def eth(src=CLIENT_MAC, dst=SERVER_MAC):
    return Ether(src=src, dst=dst)


def tcp(src, dst, sport, dport, flags, payload=b"", seq=1):
    pkt = eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                             flags=flags, seq=seq)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


def gen_benign(path: Path) -> None:
    """4 clients browsing 10.0.0.1 — full handshakes, payloads, FINs.
    Traffic density matches the benign training distribution (60+ pkt/s
    per host pair over an 8s burst window)."""
    rng = random.Random(11)
    pkts = []
    t = 1_000_000.0
    clients = ["10.0.1.11", "10.0.1.24", "10.0.1.37", "10.0.1.42"]
    for client in clients:
        for _ in range(rng.randint(12, 16)):
            sport = rng.randint(40000, 65000)
            dport = rng.choice([80, 443, 443, 80, 53])
            start = t + rng.uniform(0, 7)
            data_n = rng.randint(10, 30)
            flow = [
                tcp(client, "10.0.0.1", sport, dport, "S"),
                tcp("10.0.0.1", client, dport, sport, "SA"),
                tcp(client, "10.0.0.1", sport, dport, "A"),
            ]
            seq = 100
            for _ in range(data_n):
                load = bytes(rng.getrandbits(8) for _ in range(
                    rng.randint(200, 1200)))
                if dport == 53:
                    flow.append(tcp(client, "10.0.0.1", sport, dport, "PA",
                                    b"dns-query"))
                    flow.append(tcp("10.0.0.1", client, dport, sport, "PA",
                                    b"dns-answer"))
                else:
                    flow.append(tcp(client, "10.0.0.1", sport, dport, "PA",
                                    load, seq=seq))
                    flow.append(tcp("10.0.0.1", client, dport, sport, "A"))
                seq += len(load)
            flow += [
                tcp(client, "10.0.0.1", sport, dport, "FA"),
                tcp("10.0.0.1", client, dport, sport, "FA"),
                tcp(client, "10.0.0.1", sport, dport, "A"),
            ]
            for i, p in enumerate(flow):
                p.time = start + i * 0.008
                pkts.append(p)
    pkts.sort(key=lambda p: float(p.time))
    wrpcap(str(path), pkts)
    print(f"[samples] {path.name}: {len(pkts)} packets")


def gen_portscan(path: Path) -> None:
    """10.0.9.21 half-open scans ports 1..500 on 10.0.0.1."""
    rng = random.Random(21)
    pkts = []
    t = 2_000_000.0
    for i, dport in enumerate(range(1, 501)):
        sport = 33333
        at = t + i * 0.02
        pkts.append(_at(tcp("10.0.9.21", "10.0.0.1", sport, dport, "S"), at))
        if dport in OPEN_PORTS:
            pkts.append(_at(tcp("10.0.0.1", "10.0.9.21", dport, sport, "SA"),
                            at + 0.004))
            pkts.append(_at(tcp("10.0.9.21", "10.0.0.1", sport, dport, "R"),
                            at + 0.008))
        else:
            pkts.append(_at(tcp("10.0.0.1", "10.0.9.21", dport, sport, "RA"),
                            at + 0.004))
    pkts.sort(key=lambda p: float(p.time))
    wrpcap(str(path), pkts)
    print(f"[samples] {path.name}: {len(pkts)} packets")


def _at(pkt, ts):
    pkt.time = ts
    return pkt


def gen_synflood(path: Path, n=18000, span=6.0) -> list:
    """10.0.9.15 floods 10.0.0.1:443 with SYNs; 35% answered (then dies)."""
    rng = random.Random(15)
    pkts = []
    t = 3_000_000.0
    for i in range(n):
        sport = rng.randint(1024, 65535)
        at = t + span * i / n
        pkts.append(_at(tcp("10.0.9.15", "10.0.0.1", sport, 443, "S"), at))
        if i < int(n * 0.35):  # backlog overflows after 35%
            pkts.append(_at(tcp("10.0.0.1", "10.0.9.15", 443, sport, "SA"),
                            at + 0.0005))
    pkts.sort(key=lambda p: float(p.time))
    wrpcap(str(path), pkts)
    print(f"[samples] {path.name}: {len(pkts)} packets")
    return pkts


def gen_bruteforce(path: Path) -> None:
    """10.0.9.33 tries 150 SSH logins on 10.0.0.2 — all reset by server."""
    rng = random.Random(33)
    pkts = []
    t = 4_000_000.0
    for i in range(150):
        sport = 44000 + i
        at = t + i * 0.26
        flow = [
            tcp("10.0.9.33", "10.0.0.2", sport, 22, "S"),
            tcp("10.0.0.2", "10.0.9.33", 22, sport, "SA"),
            tcp("10.0.9.33", "10.0.0.2", sport, 22, "A"),
            tcp("10.0.0.2", "10.0.9.33", 22, sport, "PA", b"SSH-2.0-OpenSSH"),
            tcp("10.0.9.33", "10.0.0.2", sport, 22, "PA", b"auth try"),
            tcp("10.0.0.2", "10.0.9.33", 22, sport, "RA"),
        ]
        for j, p in enumerate(flow):
            p.time = at + j * 0.03
            pkts.append(p)
    pkts.sort(key=lambda p: float(p.time))
    wrpcap(str(path), pkts)
    print(f"[samples] {path.name}: {len(pkts)} packets")


def gen_mixed(path: Path) -> None:
    """Benign + scan + flood + brute force interleaved."""
    rng = random.Random(99)
    pkts = []
    t = 5_000_000.0

    # benign clients (dense short browsing bursts)
    for client in ["10.0.1.11", "10.0.1.24"]:
        for _ in range(10):
            sport = rng.randint(40000, 65000)
            dport = rng.choice([80, 443])
            start = t + rng.uniform(0, 5)
            flow = [
                tcp(client, "10.0.0.1", sport, dport, "S"),
                tcp("10.0.0.1", client, dport, sport, "SA"),
                tcp(client, "10.0.0.1", sport, dport, "A"),
            ]
            for k in range(rng.randint(12, 25)):
                load = bytes(rng.getrandbits(8) for _ in range(400))
                flow.append(tcp(client, "10.0.0.1", sport, dport, "PA", load))
                flow.append(tcp("10.0.0.1", client, dport, sport, "A"))
            flow += [
                tcp(client, "10.0.0.1", sport, dport, "FA"),
                tcp("10.0.0.1", client, dport, sport, "FA"),
            ]
            for i, p in enumerate(flow):
                p.time = start + i * 0.008
                pkts.append(p)

    # port scan (30..330)
    for i, dport in enumerate(range(30, 330)):
        at = t + 10 + i * 0.02
        pkts.append(_at(tcp("10.0.9.21", "10.0.0.1", 33333, dport, "S"), at))
        if dport in OPEN_PORTS:
            pkts.append(_at(tcp("10.0.0.1", "10.0.9.21", dport, 33333, "SA"),
                            at + 0.004))
            pkts.append(_at(tcp("10.0.9.21", "10.0.0.1", 33333, dport, "R"),
                            at + 0.008))
        else:
            pkts.append(_at(tcp("10.0.0.1", "10.0.9.21", dport, 33333, "RA"),
                            at + 0.004))

    # SYN flood (15k over 5s)
    for i in range(15000):
        sport = rng.randint(1024, 65535)
        at = t + 25 + 5.0 * i / 15000
        pkts.append(_at(tcp("10.0.9.15", "10.0.0.1", sport, 443, "S"), at))
        if i < 3500:
            pkts.append(_at(tcp("10.0.0.1", "10.0.9.15", 443, sport, "SA"),
                            at + 0.0005))

    # brute force (80 attempts)
    for i in range(80):
        sport = 45000 + i
        at = t + 35 + i * 0.2
        flow = [
            tcp("10.0.9.33", "10.0.0.2", sport, 22, "S"),
            tcp("10.0.0.2", "10.0.9.33", 22, sport, "SA"),
            tcp("10.0.9.33", "10.0.0.2", sport, 22, "A"),
            tcp("10.0.0.2", "10.0.9.33", 22, sport, "PA", b"SSH-2.0"),
            tcp("10.0.9.33", "10.0.0.2", sport, 22, "PA", b"try"),
            tcp("10.0.0.2", "10.0.9.33", 22, sport, "RA"),
        ]
        for j, p in enumerate(flow):
            p.time = at + j * 0.03
            pkts.append(p)

    pkts.sort(key=lambda p: float(p.time))
    wrpcap(str(path), pkts)
    print(f"[samples] {path.name}: {len(pkts)} packets")


def main() -> None:
    gen_benign(OUT / "benign_web.pcap")
    gen_portscan(OUT / "portscan.pcap")
    gen_synflood(OUT / "synflood.pcap")
    gen_bruteforce(OUT / "bruteforce.pcap")
    gen_mixed(OUT / "mixed_traffic.pcap")
    print("[samples] all sample pcaps written to", OUT)


if __name__ == "__main__":
    main()
