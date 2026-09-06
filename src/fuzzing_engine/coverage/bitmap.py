"""Coverage bitmap implementation (AFL-compatible edge map)."""

import hashlib
import struct
from typing import Dict, List, Optional, Set, Tuple


class CoverageBitmap:
    """AFL-compatible edge coverage bitmap.

    Uses a 64KB shared-memory-style bitmap where each byte counts
    how many times an edge (branch transition) was hit.

    Edge ID = (prev_location >> 1) ^ current_location
    """

    MAP_SIZE = 65536
    MAP_SIZE_POW2 = 16

    def __init__(self):
        self.bitmap = bytearray(self.MAP_SIZE)
        self.edges_hit: Set[int] = set()
        self.hit_count: Dict[int, int] = {}
        self._prev_location = 0
        self.total_edges = 0

    def record_edge(self, edge_id: int) -> None:
        """Record an edge hit."""
        idx = edge_id % self.MAP_SIZE
        if self.bitmap[idx] < 255:
            self.bitmap[idx] += 1
        self.edges_hit.add(edge_id)
        self.hit_count[edge_id] = self.hit_count.get(edge_id, 0) + 1
        self.total_edges = len(self.edges_hit)

    def record_trace(self, current_location: int) -> None:
        """Record a branch from previous location to current location."""
        edge_id = (self._prev_location >> 1) ^ current_location
        self.record_edge(edge_id)
        self._prev_location = current_location

    def reset_trace(self) -> None:
        """Reset trace state (call at start of each fuzz iteration)."""
        self._prev_location = 0

    def has_new_coverage(self, other: "CoverageBitmap") -> bool:
        """Check if 'other' has any edges not in self."""
        return bool(other.edges_hit - self.edges_hit)

    def get_new_edges(self, other: "CoverageBitmap") -> Set[int]:
        """Return edges in 'other' that are new to self."""
        return other.edges_hit - self.edges_hit

    def get_novelty(self, other: "CoverageBitmap") -> float:
        """Fraction of edges in 'other' that are new to self."""
        new = len(other.edges_hit - self.edges_hit)
        total = len(self.edges_hit | other.edges_hit)
        return new / max(total, 1)

    def merge(self, other: "CoverageBitmap") -> None:
        """Merge another bitmap into this one."""
        for i in range(self.MAP_SIZE):
            if other.bitmap[i]:
                self.bitmap[i] = min(255, self.bitmap[i] + other.bitmap[i])
        self.edges_hit |= other.edges_hit
        for edge_id, count in other.hit_count.items():
            self.hit_count[edge_id] = self.hit_count.get(edge_id, 0) + count
        self.total_edges = len(self.edges_hit)

    def compute_hash(self) -> str:
        """Compute a hash of the bitmap for deduplication."""
        return hashlib.sha256(self.bitmap).hexdigest()[:16]

    def get_interesting_bytes(self) -> List[int]:
        """Return bitmap indices with counts in range [1, 128] (interesting edges)."""
        return [i for i, v in enumerate(self.bitmap) if 0 < v <= 128]

    def clear(self) -> None:
        """Reset the bitmap."""
        self.bitmap = bytearray(self.MAP_SIZE)
        self.edges_hit.clear()
        self.hit_count.clear()
        self._prev_location = 0
        self.total_edges = 0

    def serialize(self) -> bytes:
        """Serialize bitmap to bytes (for storage)."""
        return bytes(self.bitmap)

    @classmethod
    def deserialize(cls, data: bytes) -> "CoverageBitmap":
        """Deserialize bitmap from bytes."""
        bitmap = cls()
        end = min(len(data), cls.MAP_SIZE)
        bitmap.bitmap[:end] = data[:end]
        # Reconstruct edge set from non-zero bytes
        for i, v in enumerate(bitmap.bitmap):
            if v:
                bitmap.edges_hit.add(i)
                bitmap.hit_count[i] = v
        bitmap.total_edges = len(bitmap.edges_hit)
        return bitmap


class MultiComponentCoverage:
    """Aggregates coverage from multiple 5GC NFs.

    Each NF contributes its own coverage bitmap. The aggregated view
    tracks which NF's coverage is stagnating, enabling the fuzzer to
    focus on under-explored components.
    """

    def __init__(self):
        self.nf_bitmaps: Dict[str, CoverageBitmap] = {}
        self.aggregated = CoverageBitmap()

    def add_nf_coverage(self, nf_name: str, bitmap: CoverageBitmap) -> None:
        """Add or update coverage for a specific NF."""
        if nf_name not in self.nf_bitmaps:
            self.nf_bitmaps[nf_name] = CoverageBitmap()
        self.nf_bitmaps[nf_name].merge(bitmap)
        self.aggregated.merge(bitmap)

    def get_stagnant_nfs(self, threshold_iterations: int = 100) -> List[str]:
        """Return NFs whose coverage has not grown recently."""
        # Simplified: return NFs with smallest total edges as proxy for underexplored
        if not self.nf_bitmaps:
            return []
        avg_edges = sum(b.total_edges for b in self.nf_bitmaps.values()) / max(len(self.nf_bitmaps), 1)
        stagnant = []
        for name, bitmap in self.nf_bitmaps.items():
            if bitmap.total_edges < avg_edges * 0.5:
                stagnant.append(name)
        return stagnant

    def get_overall_new_edges(self, new_bitmap: CoverageBitmap) -> Set[int]:
        """Get edges in new_bitmap that are novel across all NFs."""
        return self.aggregated.get_new_edges(new_bitmap)

    def clear(self) -> None:
        self.nf_bitmaps.clear()
        self.aggregated.clear()
