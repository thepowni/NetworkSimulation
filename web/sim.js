// ORWOX Network Simulation — tarayıcı tarafı.
// engine/orwox_sim ile aynı modeli (olay döngüsü, gecikme, DPI SNI kuralı, COV fragmentasyonu)
// JavaScript'e taşır. Tekrarlanabilirlik için seed'li PRNG kullanır.

(function () {
  "use strict";

  // --- Seed'li PRNG (mulberry32) -----------------------------------------
  function rng(seed) {
    let a = seed >>> 0;
    const next = () => {
      a |= 0; a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const gauss = (mu, sigma) => {
      const u = Math.max(next(), 1e-12), v = next();
      return mu + sigma * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
    };
    return { next, gauss };
  }

  // --- Olay kuyruğu (min-heap) -------------------------------------------
  class Scheduler {
    constructor() { this.clock = 0; this.heap = []; this.seq = 0; this.handlers = {}; }
    schedule(delay, target, kind, payload) {
      this.heap.push({ t: this.clock + delay, seq: this.seq++, target, kind, payload });
      this.heap.sort((a, b) => a.t - b.t || a.seq - b.seq);
    }
    register(name, fn) { this.handlers[name] = fn; }
    run(until) {
      while (this.heap.length && this.heap[0].t <= until) {
        const ev = this.heap.shift();
        this.clock = ev.t;
        const h = this.handlers[ev.target];
        if (h) h(ev);
      }
      this.clock = until;
    }
  }

  // --- TLS ClientHello üretimi ve SNI çıkarımı ---------------------------
  function clientHello(domain) {
    const host = [...domain].map(c => c.charCodeAt(0));
    const sniList = [(host.length + 3) >> 8, (host.length + 3) & 0xff, 0, host.length >> 8, host.length & 0xff, ...host];
    const extSni = [0, 0, sniList.length >> 8, sniList.length & 0xff, ...sniList];
    const body = [3, 3, ...new Array(32).fill(0), 0, 0, 2, 0x13, 0x01, 1, 0, extSni.length >> 8, extSni.length & 0xff, ...extSni];
    const hs = [1, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body];
    return [0x16, 3, 1, hs.length >> 8, hs.length & 0xff, ...hs];
  }

  function extractSni(bytes) {
    try {
      if (bytes[0] !== 0x16) return null;
      const recLen = (bytes[3] << 8) | bytes[4];
      const body = bytes.slice(5, 5 + recLen);
      if (body[0] !== 0x01) return null;
      let pos = 4 + 2 + 32;
      pos += 1 + body[pos];
      const cs = (body[pos] << 8) | body[pos + 1]; pos += 2 + cs;
      pos += 1 + body[pos];
      const extTotal = (body[pos] << 8) | body[pos + 1]; pos += 2;
      const end = pos + extTotal;
      while (pos + 4 <= end) {
        const type = (body[pos] << 8) | body[pos + 1];
        const len = (body[pos + 2] << 8) | body[pos + 3];
        const ext = body.slice(pos + 4, pos + 4 + len);
        if (type === 0) {
          const nl = (ext[3] << 8) | ext[4];
          return String.fromCharCode(...ext.slice(5, 5 + nl));
        }
        pos += 4 + len;
      }
    } catch (e) {}
    return null;
  }

  function fragment(bytes, size) {
    if (!cfg.cov) return [bytes];
    const out = [];
    for (let i = 0; i < bytes.length; i += size) out.push(bytes.slice(i, i + size));
    return out;
  }

  function isBlocked(name, list) {
    if (!name) return false;
    name = name.toLowerCase().replace(/\.$/, "");
    return list.some(b => name === b || name.endsWith("." + b));
  }

  // --- Simülasyon --------------------------------------------------------
  let cfg = {};

  function simulate(opts) {
    cfg = opts;
    const rand = rng(opts.seed);
    const sched = new Scheduler();
    const events = [];
    const results = [];
    const blocked = opts.blocked.split(",").map(s => s.trim()).filter(Boolean);

    const log = (kind, data) => events.push({ t: sched.clock.toFixed(1), kind, ...data });
    const delay = () => Math.max(0, rand.gauss(opts.latency, 6));
    const lost = () => rand.next() < opts.loss;

    sched.register("host", ev => {
      const p = ev.payload;
      if (ev.kind === "request") {
        // COV açıksa DNS, COV tarafından belirlenir (şifreli taşıma).
        const dnsVisible = !opts.cov && opts.dns === "isp";
        log("dns_query", { req: p.id, visible: dnsVisible });
        if (dnsVisible && opts.dpi && isBlocked(p.domain, blocked)) {
          log("dpi_action", { req: p.id, stage: "dns", action: opts.action });
          sched.schedule(delay(), "host", "fail", { ...p, reason: "dns:" + p.domain });
          return;
        }
        sched.schedule(delay() * 2, "host", "tcp_ready", p);
      } else if (ev.kind === "tcp_ready") {
        const hello = clientHello(p.domain);
        const frags = fragment(hello, opts.fragSize);
        log("client_hello", { req: p.id, fragments: frags.length });
        frags.forEach((f, idx) => {
          sched.schedule(idx * (opts.cov ? 2 : 0), "isp", "fragment", { ...p, frags, idx });
        });
      } else if (ev.kind === "fail") {
        log("request_failed", { req: p.id, reason: p.reason });
        results.push({ ok: false, reason: p.reason });
      } else if (ev.kind === "ok") {
        log("request_ok", { req: p.id });
        results.push({ ok: true, reason: null });
      }
    });

    // DPI modeli: parçalar birleştirilmeden (reassembly_depth = 1) yalnızca
    // ilk parça görülür; SNI ilk parçada yoksa eşleşme yapılamaz.
    sched.register("isp", ev => {
      const p = ev.payload;
      if (lost()) { log("packet_lost", { req: p.id, fragment: p.idx }); return; }
      if (p.idx === p.frags.length - 1) {
        const visible = p.frags[0];
        const sni = extractSni(visible);
        if (opts.dpi && sni && isBlocked(sni, blocked)) {
          log("dpi_action", { req: p.id, stage: "sni", action: opts.action });
          sched.schedule(delay(), "host", "fail", { ...p, reason: "sni:" + sni });
          return;
        }
        sched.schedule(delay() * 2, "host", "ok", p);
      }
    });

    for (let i = 0; i < opts.requests; i++) {
      sched.schedule(i * 100, "host", "request", { id: i, domain: opts.target });
    }
    sched.run(opts.duration);
    return { results, events };
  }

  // --- Arayüz bağlama ----------------------------------------------------
  const $ = id => document.getElementById(id);

  function renderFlow(opts) {
    const nodes = [
      ["Sunucu PC", true],
      ["COV", opts.cov],
      ["ISP / DPI", opts.dpi],
      ["Hedef", true],
    ];
    $("flow").innerHTML = nodes
      .map(([n, on]) => `<span class="node ${on ? "on" : "off"}">${n}</span>`)
      .join('<span class="arrow">→</span>');
  }

  function readOpts() {
    return {
      seed: 42,
      cov: $("cov").checked,
      dpi: $("dpi").checked,
      target: $("domain").value.trim() || "example.com",
      blocked: $("blocked").value,
      latency: +$("latency").value,
      loss: +$("loss").value / 100,
      fragSize: +$("frag").value,
      dns: $("dns").value,
      action: $("action").value,
      requests: 20,
      duration: 60000,
    };
  }

  function run() {
    const opts = readOpts();
    renderFlow(opts);
    const { results, events } = simulate(opts);
    const ok = results.filter(r => r.ok).length;
    const fail = results.length - ok;
    $("rate").textContent = results.length ? ((ok / results.length) * 100).toFixed(0) + "%" : "—";
    $("ok").textContent = ok;
    $("fail").textContent = fail;
    $("log").innerHTML = events
      .map(e => {
        const cls = /fail|dpi|lost/.test(e.kind) ? "bad" : /ok/.test(e.kind) ? "ok" : "";
        const detail = Object.entries(e).filter(([k]) => !["t", "kind"].includes(k))
          .map(([k, v]) => `${k}=${v}`).join(" ");
        return `<span class="${cls}">[${String(e.t).padStart(9)} ms] ${e.kind} ${detail}</span>`;
      })
      .join("\n");
  }

  ["latency", "loss", "frag"].forEach(id => {
    $(id).addEventListener("input", () => {
      $(id + "V") && ($(id + "V").textContent = $(id).value);
      if (id === "frag") $("fragV").textContent = $("frag").value;
    });
  });
  $("run").addEventListener("click", run);
  renderFlow(readOpts());
})();
