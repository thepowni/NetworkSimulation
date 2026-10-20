"""COV modülü: DNS konfigürasyonu + TLS ClientHello fragmentasyonu.

COV, ORWOX'un DPI bypass ve DNS yapılandırma aracıdır. İki bağımsız alt modülden
oluşur ve ayrı ayrı açılıp kapatılabilir.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DnsMode(str, Enum):
    ISP = "isp"                 # düz UDP/53
    PUBLIC_DOT = "public_dot"   # TCP/853 (TLS)
    CUSTOM_DOH = "custom_doh"   # HTTPS/443 (COV)


@dataclass
class CovConfig:
    enabled: bool = True
    dns_override_enabled: bool = True
    dns_mode: DnsMode = DnsMode.CUSTOM_DOH
    fragmentation_enabled: bool = True
    fragment_size: int = 64
    fragment_delay_ms: float = 2.0


class Cov:
    def __init__(self, cfg: CovConfig) -> None:
        self.cfg = cfg

    # --- DNS -----------------------------------------------------------------
    def effective_dns_mode(self, configured: DnsMode) -> DnsMode:
        """COV açıksa ve DNS override aktifse, DNS modu COV tarafından belirlenir."""
        if self.cfg.enabled and self.cfg.dns_override_enabled:
            return self.cfg.dns_mode
        return configured

    # --- Fragmentasyon -------------------------------------------------------
    def fragment_client_hello(self, client_hello: bytes) -> list[bytes]:
        """A4: ClientHello'yu fragment_size baytlık parçalara böler."""
        if not (self.cfg.enabled and self.cfg.fragmentation_enabled):
            return [client_hello]
        size = max(1, self.cfg.fragment_size)
        return [client_hello[i : i + size] for i in range(0, len(client_hello), size)]

    def fragment_schedule(self, n_fragments: int) -> list[float]:
        """Her parçanın gönderim gecikmesi (kümülatif, ms)."""
        return [i * self.cfg.fragment_delay_ms for i in range(n_fragments)]
