# Mimari Notları

Ayrıntılı algoritmalar ve parametre tanımları için kök dizindeki `README.md` dosyasına bakın.

## Katmanlar

| Düğüm | Modül | Sorumluluk |
|---|---|---|
| Host | `simulation.py` | İstek üretimi, DNS sorgusu, TLS ClientHello gönderimi |
| COV | `cov/cov.py` | DNS modu override, ClientHello fragmentasyonu |
| ISP/DPI | `dpi/inspector.py` | DNS qname, TLS SNI, HTTP Host incelemesi ve aksiyon |
| Link | `net/link.py` | Gecikme (Gauss jitter), paket kaybı, serileştirme |
| Çekirdek | `core/events.py` | Min-heap tabanlı ayrık olay döngüsü |

## Tasarım kararları

- **Tekrarlanabilirlik:** Tüm rastgelelik tek bir `random.Random(seed)` örneğinden gelir.
- **Soyutlama:** DPI, gerçek cihazların tüm davranışını değil, `reassembly_depth` gibi
  birkaç temel parametreyi modeller.
- **Ayrı COV bileşenleri:** DNS override ve fragmentasyon bağımsız açılıp kapatılabilir.
