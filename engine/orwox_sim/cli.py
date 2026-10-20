"""Komut satırı arayüzü: `orwox-sim run --cov on --dpi on`."""
from __future__ import annotations

import argparse
import json

from .cov.cov import CovConfig, DnsMode
from .dpi.inspector import Action, DpiConfig
from .net.link import LinkConfig
from .simulation import SimConfig, run_simulation


def _onoff(v: str) -> bool:
    return v.lower() in {"on", "true", "1", "yes", "evet"}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="orwox-sim", description="ORWOX ağ simülasyonu (COV dahil)")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="Simülasyonu çalıştır")
    r.add_argument("--seed", type=int, default=42)
    r.add_argument("--domain", default="example.com")
    r.add_argument("--blocked", default="example.com", help="Engelli alan adları (virgülle)")
    r.add_argument("--requests", type=int, default=20)
    r.add_argument("--latency", type=float, default=35.0)
    r.add_argument("--loss", type=float, default=0.002)
    r.add_argument("--dpi", type=_onoff, default=True, metavar="on|off")
    r.add_argument("--cov", type=_onoff, default=True, metavar="on|off")
    r.add_argument("--fragment-size", type=int, default=64)
    r.add_argument("--dns", choices=[m.value for m in DnsMode], default="isp")
    r.add_argument("--action", choices=[a.value for a in Action if a != Action.ALLOW], default="rst")
    r.add_argument("--json", action="store_true", help="Sonucu JSON olarak yaz")
    args = p.parse_args(argv)

    cfg = SimConfig(
        seed=args.seed,
        target_domain=args.domain,
        requests=args.requests,
        link=LinkConfig(latency_ms=args.latency, loss_rate=args.loss),
        dpi=DpiConfig(
            enabled=args.dpi,
            blocklist={d.strip() for d in args.blocked.split(",") if d.strip()},
            action_on_match=Action(args.action),
        ),
        cov=CovConfig(enabled=args.cov, fragment_size=args.fragment_size),
        dns_mode=DnsMode(args.dns),
    )
    result = run_simulation(cfg)

    if args.json:
        print(json.dumps({
            "success_rate": result.success_rate,
            "results": [r.__dict__ for r in result.results],
            "events": result.events,
        }, ensure_ascii=False, indent=2))
    else:
        print(f"COV: {'açık' if cfg.cov.enabled else 'kapalı'} | DPI: {'açık' if cfg.dpi.enabled else 'kapalı'}")
        print(f"İstek sayısı: {len(result.results)}  Başarı oranı: {result.success_rate:.1%}")
        reasons = {}
        for r_ in result.results:
            if not r_.ok:
                reasons[r_.reason] = reasons.get(r_.reason, 0) + 1
        for reason, n in reasons.items():
            print(f"  engel: {reason} x{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
