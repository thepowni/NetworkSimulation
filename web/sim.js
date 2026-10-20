(function () {
  "use strict";

  function createRandom(seed) {
    let state = seed >>> 0;
    const next = () => {
      state |= 0;
      state = (state + 0x6d2b79f5) | 0;
      let t = Math.imul(state ^ (state >>> 15), 1 | state);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const gauss = (mean, deviation) => {
      const u = Math.max(next(), 1e-12);
      const v = next();
      return mean + deviation * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
    };
    return { next, gauss };
  }

  class Scheduler {
    constructor() {
      this.clock = 0;
      this.queue = [];
      this.sequence = 0;
      this.handlers = {};
    }

    schedule(delay, target, kind, payload) {
      this.queue.push({ time: this.clock + delay, sequence: this.sequence++, target, kind, payload });
      this.queue.sort((a, b) => a.time - b.time || a.sequence - b.sequence);
    }

    register(name, handler) {
      this.handlers[name] = handler;
    }

    run(until) {
      while (this.queue.length && this.queue[0].time <= until) {
        const event = this.queue.shift();
        this.clock = event.time;
        const handler = this.handlers[event.target];
        if (handler) handler(event);
      }
      this.clock = until;
    }
  }

  function buildClientHello(domain) {
    const host = [...domain].map((c) => c.charCodeAt(0));
    const serverName = [0, host.length >> 8, host.length & 0xff, ...host];
    const serverNameList = [serverName.length >> 8, serverName.length & 0xff, ...serverName];
    const extension = [0, 0, serverNameList.length >> 8, serverNameList.length & 0xff, ...serverNameList];
    const body = [
      3, 3, ...new Array(32).fill(0),
      0,
      0, 2, 0x13, 0x01,
      1, 0,
      extension.length >> 8, extension.length & 0xff, ...extension,
    ];
    const handshake = [1, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body];
    return [0x16, 3, 1, handshake.length >> 8, handshake.length & 0xff, ...handshake];
  }

  function extractServerName(bytes) {
    try {
      if (bytes[0] !== 0x16) return null;
      const recordLength = (bytes[3] << 8) | bytes[4];
      const body = bytes.slice(5, 5 + recordLength);
      if (body[0] !== 0x01) return null;
      let pos = 4 + 2 + 32;
      pos += 1 + body[pos];
      const suites = (body[pos] << 8) | body[pos + 1];
      pos += 2 + suites;
      pos += 1 + body[pos];
      const extensionsTotal = (body[pos] << 8) | body[pos + 1];
      pos += 2;
      const end = pos + extensionsTotal;
      while (pos + 4 <= end) {
        const type = (body[pos] << 8) | body[pos + 1];
        const length = (body[pos + 2] << 8) | body[pos + 3];
        const data = body.slice(pos + 4, pos + 4 + length);
        if (type === 0) {
          const nameLength = (data[3] << 8) | data[4];
          return String.fromCharCode(...data.slice(5, 5 + nameLength));
        }
        pos += 4 + length;
      }
    } catch (error) {
      return null;
    }
    return null;
  }

  function splitBytes(bytes, size) {
    const parts = [];
    for (let i = 0; i < bytes.length; i += size) parts.push(bytes.slice(i, i + size));
    return parts;
  }

  function isBlocked(name, blockedList) {
    if (!name) return false;
    const normalized = name.toLowerCase().replace(/\.$/, "");
    return blockedList.some((b) => normalized === b || normalized.endsWith("." + b));
  }

  function simulate(options) {
    const random = createRandom(options.seed);
    const scheduler = new Scheduler();
    const events = [];
    const results = [];
    const blocked = options.blocked.split(",").map((s) => s.trim()).filter(Boolean);

    const log = (kind, data) => events.push({ time: scheduler.clock.toFixed(1), kind, ...data });
    const delay = () => Math.max(0, random.gauss(options.latency, 6));
    const lost = () => random.next() < options.loss;

    scheduler.register("host", (event) => {
      const payload = event.payload;
      if (event.kind === "request") {
        const dnsVisible = !options.cov && options.dns === "isp";
        log("dns_query", { request: payload.id, visible: dnsVisible });
        if (dnsVisible && options.dpi && isBlocked(payload.domain, blocked)) {
          log("inspector_match", { request: payload.id, stage: "dns", action: options.action });
          scheduler.schedule(delay(), "host", "failed", { ...payload, reason: "dns:" + payload.domain });
          return;
        }
        scheduler.schedule(delay() * 2, "host", "transport_ready", payload);
      } else if (event.kind === "transport_ready") {
        const hello = buildClientHello(payload.domain);
        const parts = options.cov ? splitBytes(hello, options.fragSize) : [hello];
        log("client_hello", { request: payload.id, parts: parts.length });
        parts.forEach((part, index) => {
          scheduler.schedule(index * (options.cov ? 2 : 0), "network", "segment", { ...payload, parts, index });
        });
      } else if (event.kind === "failed") {
        log("request_failed", { request: payload.id, reason: payload.reason });
        results.push({ ok: false, reason: payload.reason });
      } else if (event.kind === "succeeded") {
        log("request_succeeded", { request: payload.id });
        results.push({ ok: true, reason: null });
      }
    });

    scheduler.register("network", (event) => {
      const payload = event.payload;
      if (lost()) {
        log("packet_lost", { request: payload.id, segment: payload.index });
        return;
      }
      if (payload.index === payload.parts.length - 1) {
        const visibleServerName = extractServerName(payload.parts[0]);
        if (options.dpi && visibleServerName && isBlocked(visibleServerName, blocked)) {
          log("inspector_match", { request: payload.id, stage: "sni", action: options.action });
          scheduler.schedule(delay(), "host", "failed", { ...payload, reason: "sni:" + visibleServerName });
          return;
        }
        scheduler.schedule(delay() * 2, "host", "succeeded", payload);
      }
    });

    for (let i = 0; i < options.requests; i++) {
      scheduler.schedule(i * 100, "host", "request", { id: i, domain: options.target });
    }
    scheduler.run(options.duration);
    return { results, events };
  }

  const $ = (id) => document.getElementById(id);

  function readOptions() {
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

  function renderFlow(options) {
    const nodes = [
      ["Client host", true],
      ["COV", options.cov],
      ["ISP / DPI", options.dpi],
      ["Server", true],
    ];
    $("flow").innerHTML = nodes
      .map(([name, on]) => `<span class="node ${on ? "on" : "off"}">${name}</span>`)
      .join('<span class="arrow">→</span>');
  }

  function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function run() {
    const options = readOptions();
    renderFlow(options);
    const { results, events } = simulate(options);
    const succeeded = results.filter((r) => r.ok).length;
    const failed = results.length - succeeded;
    $("rate").textContent = results.length ? ((succeeded / results.length) * 100).toFixed(0) + "%" : "—";
    $("ok").textContent = succeeded;
    $("fail").textContent = failed;
    $("log").innerHTML = events
      .map((e) => {
        const css = /failed|match|lost/.test(e.kind) ? "bad" : /succeeded/.test(e.kind) ? "ok" : "";
        const detail = Object.entries(e)
          .filter(([key]) => key !== "time" && key !== "kind")
          .map(([key, value]) => `${key}=${escapeHtml(value)}`)
          .join(" ");
        return `<span class="${css}">[${String(e.time).padStart(9)} ms] ${e.kind} ${detail}</span>`;
      })
      .join("\n");
  }

  ["latency", "loss", "frag"].forEach((id) => {
    $(id).addEventListener("input", () => {
      $(id + "V").textContent = $(id).value;
    });
  });
  $("run").addEventListener("click", run);
  renderFlow(readOptions());
})();
