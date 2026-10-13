"use strict";

const MAX_TICKS = 260;     // flows drawn on the signal strip
const MAX_ROWS  = 250;     // flows retained in the ledger

const state = {
  flows: [],
  threshold: 0.5,
  filter: "all",
  selected: null,
  meta: null,
};

const el = (id) => document.getElementById(id);
const strip = el("strip");
const ctx = strip.getContext("2d");

const css = getComputedStyle(document.documentElement);
const COLOR = {
  attack: css.getPropertyValue("--attack").trim(),
  watch:  css.getPropertyValue("--watch").trim(),
  benign: css.getPropertyValue("--benign").trim(),
  rule:   css.getPropertyValue("--rule").trim(),
  muted:  css.getPropertyValue("--muted").trim(),
};

/* ------------------------------------------------------------------ helpers */

function band(p) {
  if (p >= state.threshold) return "attack";
  if (p >= state.threshold * 0.6) return "watch";
  return "benign";
}

const clock = (iso, ms = false) => {
  const d = new Date(iso);
  if (isNaN(d)) return "--:--:--";
  const t = d.toLocaleTimeString([], { hour12: false });
  return ms ? `${t}.${String(d.getMilliseconds()).padStart(3, "0")}` : t;
};

const endpoint = (f, side) => {
  const ip = f.meta?.[side + "_ip"];
  const port = f.meta?.[side + "_port"];
  if (!ip) return side === "src" ? "unknown source" : "unknown destination";
  return port ? `${ip}:${port}` : ip;
};

/* ------------------------------------------------------------------ signal strip */

function sizeCanvas() {
  const dpr = window.devicePixelRatio || 1;
  const w = strip.clientWidth;
  const h = strip.clientHeight;
  strip.width = w * dpr;
  strip.height = h * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  draw();
}

function draw() {
  const w = strip.clientWidth;
  const h = strip.clientHeight;
  const pad = 16;
  const plot = h - pad * 2;
  ctx.clearRect(0, 0, w, h);

  // probability gridlines
  ctx.font = '11px "IBM Plex Mono", monospace';
  ctx.textBaseline = "middle";
  for (const level of [0, 0.25, 0.5, 0.75, 1]) {
    const y = pad + plot * (1 - level);
    ctx.strokeStyle = COLOR.rule;
    ctx.globalAlpha = 0.5;
    ctx.beginPath();
    ctx.moveTo(34, y);
    ctx.lineTo(w, y);
    ctx.stroke();
    ctx.globalAlpha = 1;
    ctx.fillStyle = COLOR.muted;
    ctx.fillText(level.toFixed(2), 4, y);
  }

  // alert threshold
  const ty = pad + plot * (1 - state.threshold);
  ctx.strokeStyle = COLOR.watch;
  ctx.setLineDash([5, 4]);
  ctx.beginPath();
  ctx.moveTo(34, ty);
  ctx.lineTo(w, ty);
  ctx.stroke();
  ctx.setLineDash([]);

  // one tick per flow, oldest at the left
  const ticks = state.flows.slice(-MAX_TICKS);
  if (!ticks.length) return;
  const span = w - 42;
  const step = span / MAX_TICKS;
  const barW = Math.max(1.5, Math.min(6, step - 1.5));

  ticks.forEach((f, i) => {
    const p = f.attack_probability;
    const x = 38 + (i + (MAX_TICKS - ticks.length)) * step;
    const y = pad + plot * (1 - p);
    const kind = band(p);
    ctx.fillStyle = COLOR[kind];
    ctx.globalAlpha = kind === "benign" ? 0.5 : 0.95;
    ctx.fillRect(x, y, barW, pad + plot - y);
    if (kind === "attack") {
      ctx.globalAlpha = 1;
      ctx.fillRect(x, y - 3, barW, 2);
    }
  });
  ctx.globalAlpha = 1;
}

/* ------------------------------------------------------------------ ledger */

function rowNode(f) {
  const kind = band(f.attack_probability);
  const node = document.createElement("div");
  node.className = `row ${kind}`;
  node.dataset.id = f.id;
  node.tabIndex = 0;
  node.setAttribute("role", "button");
  node.setAttribute("aria-current", state.selected === f.id ? "true" : "false");

  const pct = Math.round(f.attack_probability * 100);
  node.innerHTML = `
    <span class="time">${clock(f.scored_at, true)}</span>
    <span class="pair">${endpoint(f, "src")} <i>to</i> ${endpoint(f, "dst")}</span>
    <span class="service">${f.meta?.protocol_name ?? ""}</span>
    <span class="score">
      <span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span>
      <span class="num">${f.attack_probability.toFixed(2)}</span>
    </span>`;

  const open = () => select(f.id);
  node.addEventListener("click", open);
  node.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
  });
  return node;
}

function passesFilter(f) {
  return state.filter === "all" || band(f.attack_probability) === "attack";
}

function emptyMessage() {
  return state.filter === "attack"
    ? "Nothing above the alert threshold yet."
    : "Flows appear here as they are scored.";
}

/* Full rebuild. Only for filter or threshold changes -- not for arriving flows. */
function renderLedger() {
  const box = el("rows");
  const visible = state.flows.filter(passesFilter);
  if (!visible.length) {
    box.innerHTML = `<p class="placeholder">${emptyMessage()}</p>`;
    return;
  }
  const frag = document.createDocumentFragment();
  for (const f of visible.slice(-MAX_ROWS).reverse()) frag.appendChild(rowNode(f));
  box.replaceChildren(frag);
  box.scrollTop = 0;
}

/*
 * Arriving flows are prepended. Rebuilding every row on each batch means the
 * ledger stops responding once the flow rate climbs, and it drops the row the
 * analyst is reading mid-click.
 */
function appendFlows(fresh) {
  const box = el("rows");
  const incoming = fresh.filter(passesFilter);
  if (!incoming.length) return;

  const placeholder = box.querySelector(".placeholder");
  if (placeholder) placeholder.remove();

  const pinned = box.scrollTop > 40;   // analyst has scrolled back: don't yank them
  const frag = document.createDocumentFragment();
  for (const f of incoming) {
    const node = rowNode(f);
    node.classList.add("new-flash");
    frag.insertBefore(node, frag.firstChild);
  }
  box.insertBefore(frag, box.firstChild);

  while (box.childElementCount > MAX_ROWS) box.lastElementChild.remove();
  if (pinned) box.scrollTop += incoming.length * 36;
}

function select(id) {
  state.selected = id;
  document.querySelectorAll(".row").forEach((r) =>
    r.setAttribute("aria-current", r.dataset.id === id ? "true" : "false"));
  renderDetail(state.flows.find((f) => f.id === id));
  document.querySelector('[data-panel="detail"]').click();
}

/* ------------------------------------------------------------------ inspector */

function verdictBlock(f) {
  const kind = band(f.attack_probability);
  const label = kind === "attack" ? "likely attack"
              : kind === "watch" ? "below threshold, worth a look"
              : "benign";
  return `
    <div class="verdict ${kind}">
      <b>${f.attack_probability.toFixed(3)}</b><span>${label}</span>
    </div>
    <div class="meter">
      <span class="fill" style="width:${f.attack_probability * 100}%;background:${COLOR[kind]}"></span>
      <span class="mark" style="left:${state.threshold * 100}%"></span>
    </div>`;
}

function renderDetail(f) {
  const panel = el("panel-detail");
  if (!f) {
    panel.innerHTML = `<p class="placeholder">Select a flow to see what drove its score.</p>`;
    return;
  }
  const m = f.meta ?? {};
  const facts = [
    ["Source", endpoint(f, "src")],
    ["Destination", endpoint(f, "dst")],
    ["Service", m.protocol_name ?? "unidentified"],
    ["Scored at", clock(f.scored_at, true)],
    ...(f.observed_at ? [["Captured at", f.observed_at]] : []),
    ["Features supplied", `${f.features_supplied} of ${state.meta?.feature_count ?? 77}`],
    ["Origin", m.source ?? "api"],
    ["Flow id", f.id],
  ];

  panel.innerHTML = `
    ${verdictBlock(f)}
    <dl class="facts">
      ${facts.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join("")}
    </dl>
    <div class="drivers">
      <h3>Inputs furthest from normal</h3>
      <p class="note">Influential features ranked by how far this flow sits from the
        training median, weighted by the forest's importance. It points at what stands
        out, not at a proven cause.</p>
      ${f.drivers.map((d) => `
        <div class="driver">
          <div class="name">${d.feature}</div>
          <div class="vals"><span>this flow <b>${d.value}</b></span>
                            <span>typical ${d.training_median}</span></div>
        </div>`).join("")}
    </div>`;
}

/* ------------------------------------------------------------------ probe */

const PROBE_FIELDS = 10;

function buildProbe(meta) {
  const box = el("probe-fields");
  box.innerHTML = meta.top_features.slice(0, PROBE_FIELDS).map((t) => `
    <div class="field">
      <label for="p-${t.feature}">${t.feature}</label>
      <input id="p-${t.feature}" data-feature="${t.feature}" type="number" step="any" placeholder="median">
    </div>`).join("");
}

async function runProbe() {
  const flow = { source: "manual probe" };
  document.querySelectorAll("#probe-fields input").forEach((input) => {
    if (input.value !== "") flow[input.dataset.feature] = Number(input.value);
  });
  const out = el("probe-result");

  if (Object.keys(flow).length === 1) {
    out.innerHTML = `<p class="error">Enter at least one value to score.</p>`;
    return;
  }

  out.innerHTML = `<p class="hint">Scoring…</p>`;
  try {
    const res = await fetch("/api/score", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(flow),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error ?? res.statusText);
    const f = data.results[0];
    out.innerHTML = verdictBlock(f) +
      `<p class="latency">answered in ${data.latency_ms} ms</p>`;
  } catch (err) {
    out.innerHTML = `<p class="error">Could not score that flow: ${err.message}</p>`;
  }
}

/* ------------------------------------------------------------------ stream */

function applyStats(s) {
  el("stat-scored").textContent = s.scored.toLocaleString();
  el("stat-attacks").textContent = s.attacks.toLocaleString();
  el("stat-rate").textContent = s.flows_per_minute.toLocaleString();
  el("stat-queue").textContent = s.queue_depth.toLocaleString();
}

function connect() {
  const source = new EventSource("/api/stream");
  const link = el("link-state");

  source.onopen = () => { link.dataset.state = "live"; };
  source.onerror = () => { link.dataset.state = "lost"; };

  source.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === "stats" || msg.type === "hello") {
      applyStats(msg.stats);
      return;
    }
    if (msg.type !== "flows") return;

    state.flows.push(...msg.flows);
    if (state.flows.length > MAX_ROWS) {
      state.flows.splice(0, state.flows.length - MAX_ROWS);
    }
    el("signal-empty").classList.add("hidden");
    draw();
    appendFlows(msg.flows);
  };
}

/* ------------------------------------------------------------------ wiring */

el("threshold").addEventListener("input", (e) => {
  state.threshold = Number(e.target.value);
  el("threshold-value").textContent = state.threshold.toFixed(2);
  draw();
  renderLedger();
  if (state.selected) renderDetail(state.flows.find((f) => f.id === state.selected));
});

el("threshold").addEventListener("change", (e) => {
  fetch("/api/threshold", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ threshold: Number(e.target.value) }),
  }).catch(() => {});
});

document.querySelectorAll(".filters button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".filters button").forEach((o) => o.classList.remove("on"));
    b.classList.add("on");
    state.filter = b.dataset.filter;
    renderLedger();
  });
});

document.querySelectorAll(".tabs button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((o) =>
      o.setAttribute("aria-selected", String(o === b)));
    el("panel-detail").classList.toggle("hidden", b.dataset.panel !== "detail");
    el("panel-probe").classList.toggle("hidden", b.dataset.panel !== "probe");
  });
});

el("probe-run").addEventListener("click", runProbe);
window.addEventListener("resize", sizeCanvas);

(async function start() {
  const meta = await fetch("/api/meta").then((r) => r.json());
  state.meta = meta;
  state.threshold = meta.threshold;
  el("threshold").value = meta.threshold;
  el("threshold-value").textContent = meta.threshold.toFixed(2);
  el("model-line").textContent =
    `${meta.estimator}, ${meta.trees} trees, ${meta.feature_count} features`;
  buildProbe(meta);
  sizeCanvas();
  connect();
})();
