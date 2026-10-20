# ORWOX Network Simulation

> Bir sunucu bilgisayarının (PC) internet trafiğinin uçtan uca nasıl işlediğini,
> DPI (Deep Packet Inspection) engellemelerinin nasıl çalıştığını ve **COV** (ORWOX'un
> DPI bypass + DNS yapılandırma aracı) bu süreçlerin neresine müdahale ettiğini
> adım adım gösteren, parametreleri değiştirilebilir bir ağ simülasyonudur.

[![Status](https://img.shields.io/badge/status-research-blue)](#)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## İçindekiler

1. [Amaç](#amaç)
2. [Kapsam](#kapsam)
3. [Hızlı Başlangıç](#hızlı-başlangıç)
4. [Mimari](#mimari)
5. [Simülasyon Modeli](#simülasyon-modeli)
6. [Parametreler](#parametreler)
7. [COV Modülü](#cov-modülü)
8. [DNS Konfigürasyonu](#dns-konfigürasyonu)
9. [Algoritmalar](#algoritmalar)
10. [Doğrulama ve Testler](#doğrulama-ve-testler)
11. [Sınırlamalar ve Etik Kullanım](#sınırlamalar-ve-etik-kullanım)
12. [Kaynaklar](#kaynaklar)

---

## Amaç

Bu proje üç temel soruya cevap vermeyi hedefler:

1. **Bir sunucu PC'nin internet alışverişi (paket gönderme/alma) gerçekte nasıl gerçekleşir?**
   Katmanlar (OSI / TCP-IP), paketlerin yönlendirilmesi, DNS çözümlemesi ve sağlayıcı (ISP) arasındaki geçişler.
2. **DPI tabanlı engelleme nasıl çalışır?** Hangi bilgiler (SNI, HTTP Host, TLS parmak izi,
   DNS sorgusu) incelenir ve hangi kararlar verilir?
3. **COV bu zincirde nerede devreye girer?** DNS yapılandırması ve paket düzeyinde
   manipülasyon (fragmentasyon, TLS record bölme vb.) ile hangi kısıtlamalar aşılır ve
   bunun ağ üzerindeki etkisi nedir?

Simülasyonun her parametresi (gecikme, paket kaybı, DPI kuralları, COV açık/kapalı durumu,
DNS sağlayıcısı, MTU vb.) ayarlanabilir; sonuçlar grafik ve olay günlüğü olarak izlenebilir.

## Kapsam

| Alan | Kapsanan | Kapsam dışı |
|---|---|---|
| Katmanlar | L2 (Ethernet benzeri), L3 (IP), L4 (TCP/UDP), L7 (HTTP/TLS/DNS) | Fiziksel katman sinyali |
| Yönlendirme | Basitleştirilmiş yönlendirme tablosu, ISP çıkış düğümü | BGP ölçekli gerçek yönlendirme |
| DPI | SNI tabanlı, HTTP Host tabanlı, DNS tabanlı, basit imza eşleştirme | Gerçek ticari DPI cihazı davranışı |
| COV | DNS yapılandırması, paket fragmentasyonu, TLS ClientHello bölme | Gerçek COV uygulamasının kaynak kodu |
| Ölçüm | Gecikme, kayıp, throughput tahmini, engel oranı | Gerçek internet ölçümü |

## Hızlı Başlangıç

```bash
git clone https://github.com/orwox/orwox-network-simulation.git
cd orwox-network-simulation

# Engine (Python 3.11+)
python -m venv .venv && source .venv/bin/activate
pip install -e ./engine

# Komut satırı simülasyonu
orwox-sim run --scenario scenarios/basic_dpi.yaml

# Web arayüzü (canlı demo)
cd web && python -m http.server 8080
# http://localhost:8080 adresini açın
```

## Mimari

```
orwox-network-simulation/
├── engine/                    # Ana simülasyon motoru (Python)
│   ├── orwox_sim/
│   │   ├── core/              # Olay döngüsü, zaman, rastgelelik
│   │   ├── net/               # Paket, katmanlar, bağlantı, yönlendirme
│   │   ├── dns/               # DNS sunucusu ve çözümleyici modelleri
│   │   ├── dpi/               # Inspection motoru, kurallar, aksiyonlar
│   │   ├── cov/               # COV modülü (bypass + DNS konfigürasyonu)
│   │   ├── isp/               # Sağlayıcı (ISP) düğümü ve politikalar
│   │   ├── host/              # Sunucu PC modeli (uygulama, soket, OS yığını)
│   │   └── metrics/           # Ölçüm, günlük, dışa aktarım
│   ├── scenarios/             # Hazır senaryolar (YAML)
│   ├── tests/
│   └── pyproject.toml
├── web/                       # Canlı site (statik + JS, engine'i WASM/JSON ile çalıştırır)
├── docs/                      # Teknik dokümantasyon
└── README.md
```

### Bileşenler

```
 ┌──────────────┐   paket    ┌──────────┐   paket    ┌────────────┐   paket    ┌──────────┐
 │ Sunucu PC    │ ─────────▶ │ COV      │ ─────────▶ │ ISP (DPI)  │ ─────────▶ │ Hedef    │
 │ (uygulama +  │            │ (opsiyon │            │ inceleme + │            │ sunucu   │
 │  DNS çözücü) │ ◀───────── │  al)     │ ◀───────── │ politika   │ ◀───────── │          │
 └──────────────┘   yanıt    └──────────┘   yanıt    └────────────┘   yanıt    └──────────┘
        │                                                  ▲
        └──── DNS sorgusu ──▶ DNS sunucusu (sağlayıcı / özel) ┘
```

## Simülasyon Modeli

Simülasyon **ayrık olay** (discrete-event) modeline dayanır. Her paket, zaman damgalı
bir olay olarak kuyruğa alınır; düğümler (host, COV, ISP, DNS, hedef) olayları işler.

### Olay döngüsü

1. Olay kuyruğu (min-heap, `(t, seq, event)`) boşalana kadar:
2. En küçük `t` değerli olayı al, simülasyon saatini `t`'ye ilerlet.
3. Olayın hedef düğümünü çağır; düğüm yeni olaylar üretebilir.
4. Ölçümleri ve günlüğü güncelle.

### Paket yaşam döngüsü (bir HTTPS isteği)

| Adım | Düğüm | İşlem |
|---|---|---|
| 1 | Host | Uygulama `example.com` çözümlemesi ister |
| 2 | Host → DNS | DNS sorgusu (UDP/53 veya DoH/443) |
| 3 | ISP-DPI | DNS sorgusunu inceler (DNS tabanlı engel kontrolü) |
| 4 | DNS | `A` kaydı yanıtı döner |
| 5 | Host | TCP 3-yönlü el sıkışması (SYN, SYN-ACK, ACK) |
| 6 | Host | TLS ClientHello (SNI = `example.com`) |
| 7 | COV (açıksa) | ClientHello'yu parçalara böler (fragmentation) |
| 8 | ISP-DPI | SNI'yı inceler; engelliyse RST veya drop uygular |
| 9 | Hedef | TLS el sıkışması tamamlanır, veri akar |

## Parametreler

Tüm parametreler `scenarios/*.yaml` veya web arayüzündeki kaydırıcılardan değiştirilebilir.

```yaml
# scenarios/basic_dpi.yaml
seed: 42
duration_ms: 60000

link:
  latency_ms: 35          # tek yön gecikme
  jitter_ms: 6            # gecikme dalgalanması (normal dağılım, σ)
  loss_rate: 0.002        # paket kayıp oranı
  mtu: 1500               # maksimum iletim birimi
  bandwidth_mbps: 50

dns:
  resolver: isp           # isp | public_doh | public_dot | custom
  dnssec: false
  cache_ttl_s: 300

dpi:
  enabled: true
  inspect:
    dns_qname: true
    tls_sni: true
    http_host: true
  blocklist:
    - example-blocked.com
  action_on_match: rst    # rst | drop | redirect | throttle
  false_positive_rate: 0.0

cov:
  enabled: true           # ← COV açık/kapalı
  dns_override:
    enabled: true
    provider: custom_doh
  tls_fragmentation:
    enabled: true
    fragment_size: 64     # ClientHello'yu bu boyuta böl
    fragment_delay_ms: 2
  http_host_mixcase: false

host:
  os: linux
  tcp_initial_cwnd: 10
  retransmit_max: 5
```

### Önemli parametreler

| Parametre | Açıklama | Etkisi |
|---|---|---|
| `link.latency_ms` | Tek yön gecikme | RTT'yi doğrudan etkiler |
| `link.loss_rate` | Paket kayıp oranı | Yeniden iletim ve throughput'u düşürür |
| `dpi.action_on_match` | Engel eşleşince aksiyon | RST, drop, throttle farklı hata profilleri üretir |
| `cov.enabled` | COV aktif mi | Açıkken DPI'nin SNI görme olasılığını düşürür |
| `cov.tls_fragmentation.fragment_size` | ClientHello parça boyutu | Çok küçük → gecikme artar; çok büyük → etki kalmaz |
| `dns.resolver` | DNS çözücü seçimi | DNS tabanlı engelin görünürlüğünü belirler |

## COV Modülü

**COV**, ORWOX'un DPI bypass ve DNS yapılandırma aracıdır. Simülasyonda iki bağımsız
alt modülden oluşur ve her biri ayrı ayrı açılıp kapatılabilir:

### 1. DNS konfigürasyonu (`cov/dns_override.py`)

- Host'un varsayılan DNS sunucusunu ISP'den özel bir çözücüye (DoH/DoT) yönlendirir.
- Böylece DNS sorgusu ISP-DPI tarafından okunamaz hale gelir (şifreli taşıma).
- Simülasyonda: `dns.resolver` değeri, DNS paketinin DPI tarafından görülüp görülmeyeceğini belirler.

### 2. Paket manipülasyonu (`cov/fragmenter.py`)

- TLS ClientHello mesajını `fragment_size` baytlık parçalara böler.
- Her parça ayrı IP/TCP segmenti olarak gönderilir; `fragment_delay_ms` aralıklarla.
- DPI motoru parçaları yeniden birleştirmeden SNI'yı göremezse, eşleşme yapamaz.
- Yeniden birleştirme (reassembly) kapasitesi `dpi.reassembly_depth` ile modellenir.

### Açma / kapama davranışı

```
cov.enabled = false  → Paket doğrudan ISP'ye gider, DNS ISP çözücüsünden geçer
cov.enabled = true   → DNS override + fragmentasyon uygulanır
```

Web arayüzünde COV bir **anahtar (toggle)** olarak gösterilir; açılıp kapatıldığında
aynı senaryo yeniden koşulur ve iki sonuç yan yana karşılaştırılır.

## DNS Konfigürasyonu

Simülasyonda DNS, üç modda çalışır:

| Mod | Taşıma | DPI görünürlüğü | Gecikme |
|---|---|---|---|
| `isp` | UDP/53 (düz) | Tam görünür | Düşük |
| `public_dot` | TCP/853 (TLS) | Sorgu gizli, IP görünür | Orta |
| `custom_doh` (COV) | HTTPS/443 (HTTP/2) | Sorgu ve IP trafik içinde karışır | Orta-yüksek |

Simülasyon, DNS yanıtının önbellekten (TTL) mi yoksa yeniden sorgudan mı geldiğini izler.

## Algoritmalar

### A1. Olay zamanlayıcı

```
function run(simulation, until):
    while queue not empty and queue.peek().time <= until:
        event = queue.pop()
        simulation.clock = event.time
        for new_event in event.node.handle(event):
            queue.push(new_event)
        metrics.record(event)
```

### A2. Gecikme ve kayıp modeli

```
delay = max(0, normal(μ = latency_ms, σ = jitter_ms))
if uniform(0,1) < loss_rate:
    drop packet
else:
    schedule delivery at clock + delay
```

### A3. DPI SNI incelemesi (basitleştirilmiş)

```
function inspect(packet_stream):
    buffer = reassemble(packet_stream, depth = reassembly_depth)
    if buffer is TLS ClientHello:
        sni = parse_sni(buffer)
        if sni in blocklist:
            return action_on_match
    return ALLOW
```

### A4. COV ClientHello fragmentasyonu

```
function fragment(client_hello, size):
    segments = []
    for offset in range(0, len(client_hello), size):
        segments.append(client_hello[offset : offset + size])
    return segments   # her parça ayrı TCP segmenti olarak, fragment_delay_ms aralıkla gönderilir
```

Not: Bu algoritma yalnızca **simülasyon modelidir**. DPI'nin hangi durumda parçaları
birleştirebildiği, `reassembly_depth` parametresiyle soyutlanır.

### A5. DNS önbellek (TTL)

```
function resolve(qname):
    if cache.has(qname) and cache[qname].expires > clock:
        return cache[qname].value      # önbellekten
    answer = upstream.query(qname)     # ISP veya özel çözücü
    cache[qname] = (answer, clock + ttl)
    return answer
```

## Doğrulama ve Testler

```bash
cd engine
pytest -q
```

- **Birim testler**: her katman (paket, gecikme modeli, DPI kuralları, fragmentasyon) için.
- **Özellik testleri**: `cov.enabled=true` iken SNI engelinin oranı, `false` iken oranından
  anlamlı şekilde düşük olmalıdır (istatistiksel test, belirli seed ile tekrarlanabilir).
- **Tekrarlanabilirlik**: aynı `seed` her zaman aynı sonucu üretir.

## Sınırlamalar ve Etik Kullanım

- Bu bir **model**dir; gerçek ISP altyapısı, gerçek DPI cihazları veya gerçek COV
  uygulamasının kodu içermez.
- Sonuçlar gerçek internet ölçümlerinin yerine geçmez.
- Proje **eğitim ve araştırma** amaçlıdır: ağ mühendisliği, sansür tekniklerinin
  anlaşılması ve savunma (DPI tespiti) geliştirmek için tasarlanmıştır.
- Gerçek sistemlere karşı kullanım, yasal sınırların ihlali veya başkalarının
  iletişimine müdahale amacıyla kullanılması yasaktır ve bu projenin kapsamı dışındadır.

## Kaynaklar

- RFC 791 (IPv4), RFC 793 (TCP), RFC 8446 (TLS 1.3), RFC 8484 (DNS over HTTPS), RFC 7858 (DNS over TLS)
- RFC 6066 §3 (TLS Server Name Indication)
- Kurose & Ross, *Computer Networking: A Top-Down Approach*

---

Bu proje [ORWOX](https://orwox.example) ekibi tarafından geliştirilmektedir. Lisans: MIT.
