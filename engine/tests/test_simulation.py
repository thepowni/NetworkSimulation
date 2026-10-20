"""Temel birim ve özellik testleri."""
import random

from orwox_sim.cov.cov import Cov, CovConfig, DnsMode
from orwox_sim.dpi.inspector import Action, DpiConfig, DpiInspector, extract_sni
from orwox_sim.net.link import Link, LinkConfig
from orwox_sim.simulation import SimConfig, _client_hello, run_simulation


def test_sni_roundtrip():
    hello = _client_hello("example.com")
    assert extract_sni(hello) == "example.com"


def test_sni_garbage_returns_none():
    assert extract_sni(b"\x00\x01\x02") is None


def test_dpi_blocks_subdomain():
    dpi = DpiInspector(DpiConfig(blocklist={"example.com"}), random.Random(0))
    assert dpi.inspect_dns("www.example.com").action == Action.RST


def test_cov_fragments_cover_whole_message():
    cov = Cov(CovConfig(fragment_size=10))
    msg = bytes(range(95))
    frags = cov.fragment_client_hello(msg)
    assert b"".join(frags) == msg
    assert all(len(f) <= 10 for f in frags)


def test_fragmented_hello_hides_sni_from_shallow_dpi():
    cov = Cov(CovConfig(fragment_size=16))
    frags = cov.fragment_client_hello(_client_hello("example.com"))
    dpi = DpiInspector(DpiConfig(blocklist={"example.com"}, reassembly_depth=1), random.Random(0))
    # Tek parça görünür: SNI çıkarılamaz, engel uygulanmaz
    assert dpi.inspect_tls_fragments(frags).action == Action.ALLOW


def test_link_loss_rate_is_respected():
    link = Link(LinkConfig(loss_rate=0.5), random.Random(1))
    drops = sum(link.is_dropped() for _ in range(10_000))
    assert 4_700 < drops < 5_300


def test_same_seed_is_reproducible():
    a = run_simulation(SimConfig(seed=7))
    b = run_simulation(SimConfig(seed=7))
    assert [r.ok for r in a.results] == [r.ok for r in b.results]


def test_cov_improves_success_rate():
    base = dict(seed=42, requests=50)
    off = run_simulation(SimConfig(**base, cov=CovConfig(enabled=False),
                                   dpi=DpiConfig(blocklist={"example.com"})))
    on = run_simulation(SimConfig(**base, cov=CovConfig(enabled=True),
                                  dpi=DpiConfig(blocklist={"example.com"})))
    assert on.success_rate > off.success_rate
