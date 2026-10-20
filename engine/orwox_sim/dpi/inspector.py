"""DPI inceleme motoru (basitleştirilmiş).

Gerçek DPI cihazlarının davranışı soyutlanmıştır. Model şunları yapar:
  * DNS sorgu adını (qname) inceler
  * TLS ClientHello içindeki SNI alanını çıkarır
  * HTTP Host başlığını inceler
  * Parçalı (fragmented) ClientHello'yu, `reassembly_depth` kadar yeniden birleştirir
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Action(str, Enum):
    ALLOW = "allow"
    RST = "rst"
    DROP = "drop"
    THROTTLE = "throttle"


@dataclass
class DpiConfig:
    enabled: bool = True
    inspect_dns_qname: bool = True
    inspect_tls_sni: bool = True
    inspect_http_host: bool = True
    blocklist: set[str] = field(default_factory=set)
    action_on_match: Action = Action.RST
    false_positive_rate: float = 0.0
    reassembly_depth: int = 1        # 1 = parçaları birleştirmez (tek paket incelenir)


@dataclass
class Verdict:
    action: Action
    reason: Optional[str] = None


class DpiInspector:
    def __init__(self, cfg: DpiConfig, rng) -> None:
        self.cfg = cfg
        self.rng = rng

    def _is_blocked(self, name: Optional[str]) -> bool:
        if not name:
            return False
        name = name.lower().rstrip(".")
        return any(name == b or name.endswith("." + b) for b in self.cfg.blocklist)

    def inspect_dns(self, qname: str) -> Verdict:
        if not (self.cfg.enabled and self.cfg.inspect_dns_qname):
            return Verdict(Action.ALLOW)
        if self._is_blocked(qname):
            return Verdict(self.cfg.action_on_match, f"dns:{qname}")
        return Verdict(Action.ALLOW)

    def inspect_tls_fragments(self, fragments: list[bytes]) -> Verdict:
        """Parçalı ClientHello'yu, reassembly_depth kadar birleştirip SNI arar."""
        if not (self.cfg.enabled and self.cfg.inspect_tls_sni):
            return Verdict(Action.ALLOW)
        visible = fragments[: self.cfg.reassembly_depth]
        buffer = b"".join(visible)
        sni = extract_sni(buffer)
        if sni is None:
            # Parça birleşmediyse SNI görünmez: DPI eşleştiremez.
            return Verdict(Action.ALLOW, "sni-not-visible")
        if self._is_blocked(sni):
            return Verdict(self.cfg.action_on_match, f"sni:{sni}")
        return Verdict(Action.ALLOW)

    def inspect_http_host(self, host: str) -> Verdict:
        if not (self.cfg.enabled and self.cfg.inspect_http_host):
            return Verdict(Action.ALLOW)
        if self._is_blocked(host):
            return Verdict(self.cfg.action_on_match, f"http-host:{host}")
        return Verdict(Action.ALLOW)


def extract_sni(client_hello: bytes) -> Optional[str]:
    """TLS ClientHello'dan server_name (SNI, RFC 6066 §3) alanını çıkarır.

    Yapı: Record(5) -> Handshake(4) -> ClientHello -> extensions -> server_name(0x0000).
    Hatalı/eksik veri için None döner.
    """
    try:
        if len(client_hello) < 5 or client_hello[0] != 0x16:   # 0x16 = handshake
            return None
        rec_len = int.from_bytes(client_hello[3:5], "big")
        body = client_hello[5 : 5 + rec_len]
        if not body or body[0] != 0x01:                         # 0x01 = ClientHello
            return None
        pos = 4 + 2 + 32                                        # hs header + version + random
        sid_len = body[pos]; pos += 1 + sid_len
        cs_len = int.from_bytes(body[pos : pos + 2], "big"); pos += 2 + cs_len
        cm_len = body[pos]; pos += 1 + cm_len
        ext_total = int.from_bytes(body[pos : pos + 2], "big"); pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type = int.from_bytes(body[pos : pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2 : pos + 4], "big")
            ext = body[pos + 4 : pos + 4 + ext_len]
            if ext_type == 0x0000:                              # server_name
                name_len = int.from_bytes(ext[3:5], "big")
                return ext[5 : 5 + name_len].decode("ascii", errors="ignore")
            pos += 4 + ext_len
        return None
    except (IndexError, ValueError):
        return None
