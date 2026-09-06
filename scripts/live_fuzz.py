#!/usr/bin/env python3
"""Live fuzzing against a running 5GC deployment.

Connects to the real Open5GS cluster (already running):
  - AMF:  172.22.0.10:38412 (SCTP — NGAP + NAS injection)
  - UPF:  172.22.0.8:8805 (UDP — PFCP injection)
  - UPF:  172.22.0.8:2152 (UDP — GTP-U injection)

Monitors Docker container logs for crash signals (SIGSEGV, SIGABRT,
ASAN errors, etc.) and records coverage data.

Usage:
  python scripts/live_fuzz.py --iterations 1000 --protocol nas
  python scripts/live_fuzz.py --iterations 5000 --all-protocols
"""

import argparse
import json
import logging
import random
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import ProtocolType, FiveGCImpl, NFType, CrashRecord, CrashSeverity
from src.codec.nas_codec import NAS5GSCodec
from src.codec.ngap_codec import NGAPCodec
from src.codec.pfcp_codec import PFCPCodec
from src.codec.gtpu_codec import GTPUCodec
from src.codec.base import ParsedMessage
from src.fuzzing_engine.mutator import (
    BitFlipMutation, StructurePreservingMutation,
)
from src.fuzzing_engine.seed_manager import Seed
from src.triage.crash_triage import CrashTriage
from src.feedback.analyzer import FeedbackAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("live_fuzz")

# ─── 5GC target addresses ───────────────────────────────────────
# Auto-discovered from running Docker containers; fallback defaults below

def _discover_5gc_hosts():
    """Discover running 5GC NF containers and their IPs."""
    import json
    try:
        # Find containers on 5GC Docker networks
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Networks}}"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return {}

    hosts = {}
    for line in result.stdout.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, networks = parts[0], parts[1]

        try:
            inspect = subprocess.run(
                ["docker", "inspect", name,
                 "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"],
                capture_output=True, text=True, timeout=3,
            )
            ips = inspect.stdout.strip().split()
        except Exception:
            continue

        for ip in ips:
            if ip.startswith("172."):
                if "amf" in name.lower():
                    hosts.setdefault("amf", ip)
                elif "upf" in name.lower():
                    hosts.setdefault("upf", ip)
                elif "smf" in name.lower():
                    hosts.setdefault("smf", ip)
                elif "mongo" in name.lower() or "mongod" in name.lower():
                    hosts.setdefault("mongo", ip)
    return hosts

_hosts = _discover_5gc_hosts()

AMF_HOST = _hosts.get("amf", "172.22.0.10")
AMF_PORT = 38412
UPF_HOST = _hosts.get("upf", "172.22.0.8")
UPF_PFCP_PORT = 8805
UPF_GTPU_PORT = 2152
MONGO_HOST = _hosts.get("mongo", "172.22.0.2")
MONGO_PORT = 27017

# Container names for log monitoring
CONTAINERS = [
    "amf", "smf", "upf", "ausf", "udm", "udr",
    "pcf", "nssf", "bsf", "scp", "nrf",
]


class LiveFuzzer:
    """Fuzzer that connects to a live 5GC deployment."""

    def __init__(self, iterations: int = 1000, protocol: str = "nas"):
        self.iterations = iterations
        self.protocol = protocol
        self.nas_codec = NAS5GSCodec()
        self.ngap_codec = NGAPCodec()
        self.pfcp_codec = PFCPCodec()
        self.gtpu_codec = GTPUCodec()

        self.bitflip = BitFlipMutation()
        self.struct = StructurePreservingMutation()

        self.triage = CrashTriage()
        self.analyzer = FeedbackAnalyzer()

        self.crashes: List[CrashRecord] = []
        self.stats: Dict[str, Any] = defaultdict(int)

        self._sctp_sock: Optional[socket.socket] = None
        self._pfcp_sock: Optional[socket.socket] = None
        self._gtpu_sock: Optional[socket.socket] = None

    # ─── Connection management ──────────────────────────────────

    def connect(self) -> bool:
        """Establish connections to 5GC NFs."""
        results = []

        if self.protocol in ("nas", "ngap", "all"):
            results.append(("AMF (SCTP)", self._connect_sctp()))
        if self.protocol in ("pfcp", "all"):
            results.append(("UPF (PFCP)", self._connect_pfcp()))
        if self.protocol in ("gtpu", "all"):
            results.append(("UPF (GTP-U)", self._connect_gtpu()))

        for name, ok in results:
            status = "OK" if ok else "FAILED"
            logger.info(f"  {name}: {status}")

        return any(ok for _, ok in results)

    def _connect_sctp(self) -> bool:
        try:
            self._sctp_sock = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM, 132  # IPPROTO_SCTP
            )
            self._sctp_sock.settimeout(3.0)
            self._sctp_sock.connect((AMF_HOST, AMF_PORT))
            logger.info(f"SCTP connected to AMF {AMF_HOST}:{AMF_PORT}")
            return True
        except OSError as e:
            logger.warning(f"SCTP connect failed: {e}")
            try:
                self._sctp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sctp_sock.settimeout(3.0)
                self._sctp_sock.connect((AMF_HOST, AMF_PORT))
                logger.info(f"TCP fallback to AMF {AMF_HOST}:{AMF_PORT}")
                return True
            except OSError as e2:
                logger.error(f"TCP fallback also failed: {e2}")
                return False

    def _connect_pfcp(self) -> bool:
        try:
            self._pfcp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._pfcp_sock.settimeout(2.0)
            logger.info(f"PFCP UDP ready for {UPF_HOST}:{UPF_PFCP_PORT}")
            return True
        except OSError as e:
            logger.error(f"PFCP socket: {e}")
            return False

    def _connect_gtpu(self) -> bool:
        try:
            self._gtpu_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._gtpu_sock.settimeout(2.0)
            logger.info(f"GTP-U UDP ready for {UPF_HOST}:{UPF_GTPU_PORT}")
            return True
        except OSError as e:
            logger.error(f"GTP-U socket: {e}")
            return False

    def disconnect(self) -> None:
        for sock in [self._sctp_sock, self._pfcp_sock, self._gtpu_sock]:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    # ─── Message generation ─────────────────────────────────────

    def _make_nas_seed(self) -> bytes:
        """Generate a valid NAS Registration Request PDU."""
        msg = ParsedMessage(
            protocol="nas-5gs",
            message_type="Registration Request",
            message_name="Registration Request",
            fields={
                "5gs_registration_type": 1,
                "ng_ksi": 0,
                "5gs_mobile_identity_supi": "001010123456789",
            },
        )
        return self.nas_codec.encode(msg)

    def _make_ngap_nas_seed(self) -> bytes:
        """Wrap NAS PDU in NGAP InitialUEMessage."""
        nas_pdu = self._make_nas_seed()
        msg = ParsedMessage(
            protocol="ngap",
            message_type="InitialUEMessage",
            message_name="InitialUEMessage",
            fields={
                "ran_ue_ngap_id": random.randint(1, 100),
                "nas_pdu": nas_pdu,
            },
        )
        return self.ngap_codec.encode(msg)

    def _make_pfcp_seed(self) -> bytes:
        msg = self.pfcp_codec.random_valid("PFCP Association Setup Request")
        return self.pfcp_codec.encode(msg)

    def _make_gtpu_seed(self) -> bytes:
        msg = self.gtpu_codec.random_valid("G-PDU")
        return self.gtpu_codec.encode(msg)

    # ─── Injection ──────────────────────────────────────────────

    def inject_sctp(self, data: bytes) -> Optional[bytes]:
        """Send data via SCTP to AMF (fire-and-forget, no response wait)."""
        if not self._sctp_sock:
            return None
        try:
            self._sctp_sock.setblocking(False)
            self._sctp_sock.sendall(data)
            # Don't wait for response — blast mode for fuzzing
            self._sctp_sock.setblocking(True)
        except (OSError, BrokenPipeError, BlockingIOError) as e:
            logger.debug(f"SCTP inject error: {e}")
            try:
                self._connect_sctp()
            except Exception:
                pass
        return None

    def inject_udp(self, sock: Optional[socket.socket],
                    host: str, port: int, data: bytes
                    ) -> None:
        """Send data via UDP (fire-and-forget for high-speed fuzzing)."""
        if not sock:
            return
        try:
            sock.sendto(data, (host, port))
        except OSError as e:
            pass  # Don't log every failure at speed

    # ─── Crash detection ────────────────────────────────────────

    def check_crashes(self) -> List[CrashRecord]:
        """Check Docker container logs for crash signals."""
        crashes = []
        crash_patterns = [
            b"SIGSEGV", b"SIGABRT", b"SIGILL", b"SIGBUS", b"SIGFPE",
            b"segmentation fault", b"segfault", b"core dumped",
            b"AddressSanitizer", b"heap-buffer-overflow",
            b"stack-buffer-overflow", b"heap-use-after-free",
            b"double-free", b"null-deref", b"integer-overflow",
            b"UndefinedBehaviorSanitizer", b"ubsan",
            b"assertion failed", b"assertion",
        ]

        for container_name in CONTAINERS:
            try:
                result = subprocess.run(
                    ["docker", "logs", container_name, "--since", "10s"],
                    capture_output=True, timeout=5,
                    text=False,
                )
                if result.stderr or result.stdout:
                    log_data = result.stderr + result.stdout
                    for pattern in crash_patterns:
                        if pattern in log_data:
                            lines = log_data.split(b"\n")
                            for line in lines:
                                if pattern in line:
                                    crash = CrashRecord(
                                        crash_signal=pattern.decode("ascii", errors="replace"),
                                        target_nf=NFType.AMF,  # Infer from container
                                        crash_address=0,
                                        raw_log=line.decode("utf-8", errors="replace"),
                                        severity=CrashSeverity.CRITICAL,
                                        input_pdu=b"",
                                    )
                                    crashes.append(crash)
                                    logger.warning(f"CRASH in {container_name}: {pattern.decode()}")
            except (subprocess.TimeoutExpired, Exception):
                pass

        return crashes

    # ─── Main fuzz loop ─────────────────────────────────────────

    def run(self) -> Dict[str, Any]:
        """Run the live fuzzing campaign."""
        logger.info(f"Starting live fuzzing: {self.iterations} iterations, protocol={self.protocol}")

        if not self.connect():
            logger.error("No connections established. Check 5GC deployment.")
            return {"error": "connection_failed"}

        for i in range(self.iterations):
            # Step 1: Generate seed PDU
            if self.protocol in ("nas", "ngap", "all"):
                if random.random() < 0.5:
                    seed_data = self._make_ngap_nas_seed()
                    proto = "ngap+ncp"
                else:
                    seed_data = self._make_nas_seed()
                    proto = "nas"
            elif self.protocol == "pfcp":
                seed_data = self._make_pfcp_seed()
                proto = "pfcp"
            elif self.protocol == "gtpu":
                seed_data = self._make_gtpu_seed()
                proto = "gtpu"
            else:
                continue

            # Step 2: Mutate using individual strategies
            seed = Seed(raw_pdu=seed_data, protocol=proto)
            ctx = type('Ctx', (), {'protocol': proto, 'generation': 1, 'random': random})()
            strategy = self.bitflip  # BitFlip works without codec context
            mutated = strategy.mutate(seed, ctx)

            # Step 3: Inject
            if self._sctp_sock:
                # NGAP needs wrapping if we have raw NAS
                if self.protocol == "nas" and len(mutated) > 0:
                    ngap_msg = ParsedMessage(
                        protocol="ngap", message_type="UplinkNASTransport",
                        message_name="UplinkNASTransport",
                        fields={
                            "amf_ue_ngap_id": random.randint(1, 100),
                            "ran_ue_ngap_id": random.randint(1, 100),
                            "nas_pdu": mutated,
                        },
                    )
                    mutated = self.ngap_codec.encode(ngap_msg)
                self.inject_sctp(mutated)

            if self._pfcp_sock:
                self.inject_udp(
                    self._pfcp_sock, UPF_HOST, UPF_PFCP_PORT,
                    mutated[:512],  # Truncate for PFCP
                )

            if self._gtpu_sock:
                self.inject_udp(
                    self._gtpu_sock, UPF_HOST, UPF_GTPU_PORT,
                    mutated if len(mutated) < 1500 else mutated[:1500],
                )

            # Step 4: Check for crashes (every 50 iterations)
            if i % 50 == 0:
                new_crashes = self.check_crashes()
                if new_crashes:
                    self.crashes.extend(new_crashes)
                    for c in new_crashes:
                        logger.warning(f"  Crash: {c.crash_signal} severity={c.severity}")

            # Step 5: Progress
            if i % 200 == 0:
                logger.info(f"Iteration {i}/{self.iterations} "
                           f"({len(self.crashes)} crashes so far)")

            self.stats["iterations"] = i + 1

        self.disconnect()
        return self._compile_results()

    def _compile_results(self) -> Dict[str, Any]:
        """Compile campaign results."""
        groups = self.triage.triage(self.crashes)
        stats = self.triage.get_statistics()

        return {
            "total_iterations": self.stats["iterations"],
            "unique_crashes": len(groups),
            "total_crashes": len(self.crashes),
            "crash_groups": [{
                "root_cause": g.root_cause,
                "severity": g.representative.severity.value,
                "members": len(g.members),
            } for g in groups],
            "severity_distribution": stats.get("severity_distribution", {}),
            "root_cause_distribution": stats.get("root_cause_distribution", {}),
        }


def main():
    parser = argparse.ArgumentParser(description="Live 5G fuzzing")
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--protocol", choices=["nas", "ngap", "pfcp", "gtpu", "all"],
                       default="nas")
    parser.add_argument("--output", type=str, default="./results/live_fuzz.json")
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("LIVE 5G FUZZING")
    print("=" * 60)
    print(f"Iterations: {args.iterations}")
    print(f"Protocol:   {args.protocol}")
    print(f"Targets:    AMF={AMF_HOST}:{AMF_PORT}, UPF={UPF_HOST}:{UPF_PFCP_PORT}/{UPF_GTPU_PORT}")
    print("=" * 60 + "\n")

    fuzzer = LiveFuzzer(iterations=args.iterations, protocol=args.protocol)
    results = fuzzer.run()

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Iterations:    {results['total_iterations']}")
    print(f"Total crashes: {results['total_crashes']}")
    print(f"Unique:        {results['unique_crashes']}")

    if results.get("crash_groups"):
        print("\nCrash Details:")
        for g in results["crash_groups"]:
            print(f"  {g['root_cause']} ({g['severity']}): {g['members']} crashes")

    if results.get("severity_distribution"):
        print(f"\nSeverity: {results['severity_distribution']}")
    if results.get("root_cause_distribution"):
        print(f"Root causes: {results['root_cause_distribution']}")

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to {output_path}")


if __name__ == "__main__":
    main()
