"""Core type definitions for the 5G protocol fuzzing framework."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4
import time


class ProtocolType(Enum):
    NGAP = "ngap"
    NAS = "nas"
    SBI = "sbi"
    PFCP = "pfcp"
    GTPU = "gtpu"


class FiveGCImpl(Enum):
    OPEN5GS = "open5gs"
    FREE5GC = "free5gc"
    OAI = "oai"


class NFType(Enum):
    AMF = "amf"
    SMF = "smf"
    UPF = "upf"
    NRF = "nrf"
    UDM = "udm"
    AUSF = "ausf"
    UDR = "udr"
    PCF = "pcf"
    NSSF = "nssf"
    BSF = "bsf"
    SCP = "scp"


class CrashSeverity(Enum):
    CRITICAL = "critical"  # SIGSEGV, SIGABRT - process crash
    HIGH = "high"  # SIGFPE, SIGBUS
    MEDIUM = "medium"  # Assertion failure, ASAN errors
    LOW = "low"  # Error log without crash
    INFO = "info"  # Unexpected but handled


class MutationCategory(Enum):
    BIT_FLIP = "bit_flip"
    STRUCTURE_PRESERVING = "structure_preserving"
    STATE_AWARE = "state_aware"
    CROSS_PROTOCOL = "cross_protocol"
    SEQUENCE_LEVEL = "sequence_level"
    HTTP2_SPECIFIC = "http2_specific"
    RANDOM = "random"


@dataclass
class StackFrame:
    address: Optional[int]
    function_name: Optional[str]
    file_name: Optional[str]
    line_number: Optional[int]
    raw_line: str


@dataclass
class CrashRecord:
    crash_id: UUID = field(default_factory=uuid4)
    timestamp: float = field(default_factory=time.time)
    target_impl: Optional[FiveGCImpl] = None
    target_nf: Optional[NFType] = None
    protocol: Optional[ProtocolType] = None
    seed_id: Optional[UUID] = None
    input_pdu: Optional[bytes] = None
    crash_signal: Optional[str] = None
    crash_address: Optional[int] = None
    stack_frames: List[StackFrame] = field(default_factory=list)
    asan_report: Optional[str] = None
    triage_hash: Optional[str] = None
    reproduce_script: Optional[str] = None
    severity: CrashSeverity = CrashSeverity.INFO
    root_cause_category: Optional[str] = None


@dataclass
class CoverageBitmap:
    map_size: int = 65536
    bitmap: bytearray = field(default_factory=lambda: bytearray(65536))
    edges_hit: Set[int] = field(default_factory=set)
    hit_count: Dict[int, int] = field(default_factory=dict)

    def record_edge(self, edge_id: int) -> None:
        idx = edge_id % self.map_size
        if self.bitmap[idx] < 255:
            self.bitmap[idx] += 1
        self.edges_hit.add(edge_id)
        self.hit_count[edge_id] = self.hit_count.get(edge_id, 0) + 1

    def get_novelty(self, other: "CoverageBitmap") -> float:
        new = len(other.edges_hit - self.edges_hit)
        total = len(self.edges_hit | other.edges_hit)
        return new / max(total, 1)


@dataclass
class LogEntry:
    timestamp: float
    nf_type: NFType
    level: str
    message: str
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    raw: Optional[str] = None


@dataclass
class MonitoringResult:
    logs: List[LogEntry]
    coverage_after: Optional[CoverageBitmap] = None
    coverage_before: Optional[CoverageBitmap] = None
    new_edges: Set[int] = field(default_factory=set)
    metrics: Dict[str, float] = field(default_factory=dict)
    response_times: List[float] = field(default_factory=list)
    nf_states: Dict[str, str] = field(default_factory=dict)


@dataclass
class MessageRecord:
    protocol: ProtocolType
    direction: str  # "tx" or "rx"
    raw_bytes: bytes
    message_type: Optional[str] = None
    parsed: Optional[Any] = None


@dataclass
class FuzzResult:
    iteration_id: UUID = field(default_factory=uuid4)
    target_impl: Optional[FiveGCImpl] = None
    target_nf: Optional[NFType] = None
    protocol: Optional[ProtocolType] = None
    seed_id: Optional[UUID] = None
    strategy_name: Optional[str] = None
    messages_sent: List[MessageRecord] = field(default_factory=list)
    monitoring: Optional[MonitoringResult] = None
    crash: Optional[CrashRecord] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class Feedback:
    coverage_novelty: float = 0.0
    state_reached: Optional[str] = None
    crash: Optional[CrashRecord] = None
    mutation_strategy: Optional[str] = None
    new_edges_count: int = 0
    timestamp: float = field(default_factory=time.time)
