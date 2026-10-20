"""Bağlantı (link) modeli: gecikme, jitter, kayıp, MTU."""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass
class LinkConfig:
    latency_ms: float = 35.0
    jitter_ms: float = 6.0
    loss_rate: float = 0.002
    mtu: int = 1500
    bandwidth_mbps: float = 50.0


class Link:
    def __init__(self, config: LinkConfig, rng: random.Random) -> None:
        self.cfg = config
        self.rng = rng

    def sample_delay_ms(self) -> float:
        """A2: gecikme = max(0, N(μ=latency, σ=jitter))."""
        return max(0.0, self.rng.gauss(self.cfg.latency_ms, self.cfg.jitter_ms))

    def is_dropped(self) -> bool:
        return self.rng.random() < self.cfg.loss_rate

    def transmission_ms(self, size_bytes: int) -> float:
        """Paketin hatta serileştirilme süresi (bant genişliğine göre)."""
        bits = size_bytes * 8
        return bits / (self.cfg.bandwidth_mbps * 1_000)  # Mbps -> bit/ms
