"""De-duplication helpers shared by every module."""

from __future__ import annotations

import threading
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple


class Deduplicator:
    """Thread-safe, order-preserving set with an optional counter of hits."""

    def __init__(self, lowercase: bool = False) -> None:
        self._seen: Set[str] = set()
        self._order: List[str] = []
        self._lock = threading.Lock()
        self.lowercase = lowercase

    def add(self, item: Optional[str]) -> bool:
        """Add an item. Returns True when it was new."""
        if item is None:
            return False
        key = item.strip()
        if not key:
            return False
        if self.lowercase:
            key = key.lower()
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            self._order.append(key)
            return True

    def update(self, items: Iterable[str]) -> int:
        return sum(1 for item in items if self.add(item))

    def __contains__(self, item: str) -> bool:
        key = item.strip().lower() if self.lowercase else (item or "").strip()
        with self._lock:
            return key in self._seen

    def __len__(self) -> int:
        with self._lock:
            return len(self._order)

    def items(self) -> List[str]:
        with self._lock:
            return list(self._order)

    def __iter__(self) -> Iterator[str]:
        return iter(self.items())


class Counter:
    """Thread-safe counter used for scan statistics."""

    def __init__(self) -> None:
        self._data: Dict[str, float] = {}
        self._lock = threading.Lock()

    def incr(self, key: str, amount: float = 1) -> None:
        with self._lock:
            self._data[key] = self._data.get(key, 0) + amount

    def get(self, key: str, default: float = 0) -> float:
        with self._lock:
            return self._data.get(key, default)

    def as_dict(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._data)


def unique_pairs(pairs: Iterable[Tuple[str, str]]) -> List[Tuple[str, str]]:
    seen: Set[Tuple[str, str]] = set()
    out: List[Tuple[str, str]] = []
    for a, b in pairs:
        key = (a.strip(), b.strip())
        if key in seen or not key[0] or not key[1]:
            continue
        seen.add(key)
        out.append(key)
    return out


def dedupe_lines(lines: Iterable[str], lowercase: bool = False) -> List[str]:
    dedup = Deduplicator(lowercase=lowercase)
    dedup.update(lines)
    return dedup.items()