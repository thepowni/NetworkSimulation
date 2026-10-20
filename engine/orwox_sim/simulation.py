"""Uçtan uca senaryo: Host -> (COV) -> ISP/DPI -> Hedef sunucu.

Bir HTTPS isteğinin adımlarını olay döngüsü üzerinde koşturur ve sonucu döndürür.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from .core.events import Scheduler
from .cov.cov import Cov, CovConfig, DnsMode
from .dpi.inspector import Action, DpiConfig, DpiInspector
from .net.link import Link, LinkConfig


@dataclass
class SimConfig:
    seed: int = 42
    duration_ms: float = 60_000
    link: LinkConfig = field(default_factory=LinkConfig)
    dpi: DpiConfig = field(default_factory=DpiConfig)
    cov: CovConfig = field(default_factory=CovConfig)
    dns_mode: DnsMode = DnsMode.ISP
    target_domain: str = "example.com"
    requests: int = 20


@dataclass
class RequestResult:
    domain: str
    ok: bool
    reason: str | None
    finished_ms: float


@dataclass
class SimResult:
    results: list[RequestResult] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return sum(r.ok for r in self.results) / len(self.results) if self.results else 0.0


def _client_hello(domain: str) -> bytes:
    """Minimal bir TLS ClientHello üretir (SNI içerir). Model amaçlıdır."""
    host = domain.encode("ascii")
    sni_ext_body = (len(host) + 3).to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
    extensions = b"\x00\x00" + len(sni_ext_body).to_bytes(2, "big") + sni_ext_body
    body = (
        b"\x03\x03" + bytes(32)            # version + random
        + b"\x00"                           # session id length
        + b"\x00\x02\x13\x01"               # cipher suites
        + b"\x01\x00"                       # compression
        + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def run_simulation(cfg: SimConfig) -> SimResult:
    rng = random.Random(cfg.seed)
    sched = Scheduler()
    link = Link(cfg.link, rng)
    dpi = DpiInspector(cfg.dpi, rng)
    cov = Cov(cfg.cov)
    out = SimResult()

    def log(kind: str, **data: Any) -> None:
        out.events.append({"t": round(sched.clock_ms, 2), "kind": kind, **data})

    def start_request(i: int) -> None:
        sched.schedule(0, "host", "request", {"id": i, "domain": cfg.target_domain})

    def host(ev) -> list:
        p = ev.payload
        if ev.kind == "request":
            effective = cov.effective_dns_mode(cfg.dns_mode)
            log("dns_query", req=p["id"], mode=effective.value)
            # DNS sorgusu: düz UDP ise DPI qname'i görebilir.
            if effective == DnsMode.ISP:
                v = dpi.inspect_dns(p["domain"])
                if v.action != Action.ALLOW:
                    log("dpi_action", req=p["id"], stage="dns", action=v.action.value)
                    sched.schedule(link.sample_delay_ms(), "host", "fail", {**p, "reason": v.reason})
                    return []
            sched.schedule(link.sample_delay_ms() * 2, "host", "tcp_ready", p)
        elif ev.kind == "tcp_ready":
            # TLS ClientHello gönder (parçalı olabilir)
            frags = cov.fragment_client_hello(_client_hello(p["domain"]))
            log("client_hello", req=p["id"], fragments=len(frags))
            for idx, sched_off in enumerate(cov.fragment_schedule(len(frags))):
                sched.schedule(sched_off, "isp", "fragment", {**p, "frags": frags, "idx": idx})
        elif ev.kind == "fail":
            log("request_failed", req=p["id"], reason=p.get("reason"))
            out.results.append(RequestResult(p["domain"], False, p.get("reason"), sched.clock_ms))
        elif ev.kind == "ok":
            log("request_ok", req=p["id"])
            out.results.append(RequestResult(p["domain"], True, None, sched.clock_ms))
        return []

    def isp(ev) -> list:
        p = ev.payload
        if ev.kind != "fragment":
            return []
        if link.is_dropped():
            log("packet_lost", req=p["id"], fragment=p["idx"])
            return []
        # Parçaları DPI, yalnızca ilk 'reassembly_depth' kadar görebilir.
        if p["idx"] == len(p["frags"]) - 1:
            v = dpi.inspect_tls_fragments(p["frags"])
            if v.action != Action.ALLOW:
                log("dpi_action", req=p["id"], stage="sni", action=v.action.value, reason=v.reason)
                sched.schedule(link.sample_delay_ms(), "host", "fail", {**p, "reason": v.reason})
                return []
            sched.schedule(link.sample_delay_ms() * 2, "host", "ok", p)
        return []

    sched.register("host", host)
    sched.register("isp", isp)
    sched.observe(lambda e: None)

    for i in range(cfg.requests):
        sched.schedule(i * 100.0, "host", "request", {"id": i, "domain": cfg.target_domain})
    sched.run(cfg.duration_ms)
    return out
