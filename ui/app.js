"use strict";
// Proxy on demand: the window. Python sends events (ui.receive); the page calls window.pywebview.api.

const ICONS = {
  shield: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  home: '<path d="M4 11l8-7 8 7"/><path d="M6 10v10h12V10"/><path d="M10 20v-6h4v6"/>',
  receipt: '<path d="M6 3h12v18l-3-2-3 2-3-2-3 2z"/><path d="M9 8h6M9 12h6M9 16h4"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6"/><path d="M16 4.5a3.5 3.5 0 010 7M18 14c2 .6 3 2.8 3 6"/>',
  list: '<path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1"/><circle cx="4.5" cy="12" r="1"/><circle cx="4.5" cy="18" r="1"/>',
  moon: '<path d="M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  settings: '<path d="M10.3 4.3c.4-1.8 3-1.8 3.4 0a1.7 1.7 0 002.6 1.1c1.5-.9 3.3.8 2.4 2.4a1.7 1.7 0 001 2.5c1.8.4 1.8 3 0 3.4a1.7 1.7 0 00-1 2.6c.9 1.5-.9 3.3-2.4 2.4a1.7 1.7 0 00-2.6 1c-.4 1.8-3 1.8-3.4 0a1.7 1.7 0 00-2.5-1c-1.6.9-3.3-.9-2.4-2.4a1.7 1.7 0 00-1.1-2.6c-1.8-.4-1.8-3 0-3.4a1.7 1.7 0 001.1-2.5c-.9-1.6.8-3.3 2.4-2.4 1 .6 2.3.1 2.5-1.1z"/><circle cx="12" cy="12" r="3"/>',
  server: '<rect x="4" y="4" width="16" height="7" rx="2"/><rect x="4" y="13" width="16" height="7" rx="2"/><path d="M8 7.5h.01M8 16.5h.01"/>',
  laptop: '<rect x="5" y="5" width="14" height="10" rx="1.5"/><path d="M3 19h18"/>',
  desktop: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M9 20h6M12 16v4"/>',
  world: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
  link: '<path d="M10 14a4 4 0 005.7 0l3-3a4 4 0 00-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 00-5.7 0l-3 3a4 4 0 005.7 5.7l1-1"/>',
  alert: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 00-1-1H5a1 1 0 00-1 1v10a1 1 0 001 1h3"/>',
  refresh: '<path d="M20 11a8 8 0 00-14.9-3M4 5v3h3M4 13a8 8 0 0014.9 3M20 19v-3h-3"/>',
  folder: '<path d="M3 6a1 1 0 011-1h5l2 2h9a1 1 0 011 1v10a1 1 0 01-1 1H4a1 1 0 01-1-1z"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
};
const icon = (name, size = 20) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ""}</svg>`;
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = () => window.pywebview.api;
const money = (v, digits = 2) => v == null ? "—" : v > 0 && v < 0.01 && digits === 2 ? "<$0.01" : "$" + v.toFixed(digits);
const gb = (b) => (b / 1e9).toFixed(1);
const hm = (h) => `${Math.floor(h)}h ${String(Math.floor((h * 60) % 60)).padStart(2, "0")}m`;
const cap = (s) => s ? s[0].toUpperCase() + s.slice(1) : "";
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
function setHTML(el, html) { if (el && el.__html !== html) { el.innerHTML = html; el.__html = html; drawIcons(el); } }
function drawIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((el) => { el.innerHTML = icon(el.dataset.icon, +el.dataset.size || 20); el.removeAttribute("data-icon"); });
}

const state = {
  page: "home", mode: "own", busy: false, status: ["Checking", "busy", ""], startLabel: "Start",
  route: null, tiles: null, plan: null, sharing: { state: "off", peers: null }, policy: [], update: null,
  quit: null, mfa: false, notices: [], log: [], texts: {}, device: "This PC", settingsForm: null, policyGuide: null,
  agreement: null,
};
let noticeId = 0;

// ---- events from Python
window.ui = {
  receive(events) {
    for (const [kind, msg] of events) {
      switch (kind) {
        case "status": state.status = msg; break;
        case "busy": state.busy = true; state.progress = null; break;
        case "progress": state.progress = msg; break;
        case "done": state.busy = false; state.progress = null; break;
        case "mode": state.mode = msg; break;
        case "route": state.route = msg; break;
        case "tiles": state.tiles = msg; break;
        case "plan": state.plan = msg; break;
        case "sharing": state.sharing = msg; break;
        case "start_label": state.startLabel = msg; break;
        case "policy": state.policy = msg; break;
        case "update": state.update = msg; break;
        case "quit": state.quit = msg; break;
        case "mfa": state.mfa = true; go("home"); setTimeout(() => $("#mfa-code")?.focus(), 50); break;
        case "page": go(msg); break;
        case "popup": notify("ok", msg); break;
        case "warn": notify("warn", msg); break;
        case "log": state.log.push(msg); if (state.log.length > 500) state.log.shift(); break;
      }
    }
    render();
  },
};

function notify(tone, text) {
  const id = ++noticeId;
  state.notices.unshift({ id, tone, text });
  state.notices = state.notices.slice(0, 4);
  if (tone === "ok") setTimeout(() => dismiss(id), 10000);
}
function dismiss(id) { state.notices = state.notices.filter((n) => n.id !== id); render(); }

// ---- navigation
function go(page) {
  if (page === "settings") loadSettings();
  state.page = page;
  render();
  $("#main").scrollTop = 0;
}

// ---- rendering
function render() {
  const own = state.mode === "own";
  $$("[data-page]").forEach((s) => (s.hidden = s.dataset.page !== state.page));
  $(".rail").style.visibility = state.page === "choose" ? "hidden" : "";
  $$("[data-go]").forEach((b) => b.setAttribute("aria-current", b.dataset.go === state.page ? "page" : "false"));
  $$("[data-own]").forEach((el) => (el.hidden = !own));
  $("#settings-badge").hidden = !state.policy.length;
  renderBanners();
  if (state.page === "home") { renderHero(); renderRoute(); renderTiles("#tiles"); renderPlan("#plan"); renderJoin(); }
  if (state.page === "usage") { renderTiles("#tiles-2"); renderPlan("#plan-2"); renderMonth(); }
  if (state.page === "sharing") renderSharing();
  if (state.page === "activity") { const el = $("#log"); el.textContent = state.log.join("\n") || "Nothing yet."; el.scrollTop = el.scrollHeight; }
}

function banner(tone, iconName, body, actions = "", extra = "") {
  return `<div class="banner ${tone} ${extra}"><span class="ico">${icon(iconName)}</span><div class="body">${body}${actions ? `<div class="actions">${actions}</div>` : ""}</div></div>`;
}

function renderBanners() {
  const out = [];
  if (state.quit) {
    const q = state.quit;
    out.push(q.busy
      ? banner("warn", "alert", "<b>Something is still running.</b> Closing now may leave it half done.",
          `<button class="btn small" data-act="quit-force">Close anyway</button><button class="btn small ghost" data-act="quit-cancel">Keep the app open</button>`)
      : banner("warn", "alert", `<b>Your server is still running and billing.</b> Stop it before closing?${q.sharing ? " Sharing is on: anyone using your link is cut off too." : ""}`,
          `<button class="btn small primary" data-act="quit-stop">Stop server and close</button><button class="btn small" data-act="quit-keep">Keep it running and close</button><button class="btn small ghost" data-act="quit-cancel">Cancel</button>`));
  }
  if (state.mfa) {
    out.push(banner("", "key", "<b>Sign in to AWS.</b> Enter the 6-digit code from your authenticator app.<br><input type=\"text\" id=\"mfa-code\" inputmode=\"numeric\" maxlength=\"6\" autocomplete=\"one-time-code\" style=\"max-width:180px\">",
      `<button class="btn small primary" data-act="mfa-ok">Sign in</button><button class="btn small ghost" data-act="mfa-cancel">Cancel</button>`));
  }
  if (state.policy.length) {
    const what = state.policy.map((p) => ({ data: "this month's data use", bill: "AWS's figure for this app's cost" }[p] || p)).join(" and ");
    const guide = state.policyGuide
      ? `<ol>${state.policyGuide.steps.map((s) => `<li>${esc(s.replace(/^\d+\.\s*/, ""))}</li>`).join("")}</ol>`
      : "";
    out.push(banner("warn", "alert",
      `<b>Update your IAM policy.</b> This version needs new read-only permissions, so the app can't read ${esc(what)} yet.${guide}`,
      `<button class="btn small primary" data-act="policy-copy">${icon("copy", 16)}${state.policyGuide ? "Copy again" : "Copy updated policy"}</button>` +
      (state.policyGuide ? `<button class="btn small" data-act="guide" data-anchor="${esc(state.policyGuide.anchor)}">Step-by-step guide</button>` : ""),
      "strong"));
  }
  if (state.update) {
    const u = state.update;
    out.push(banner("", "download", u.kind === "git"
      ? `<b>Version ${esc(u.tag)} is available.</b> This copy is a git clone: update it with <code>git pull</code>.`
      : `<b>Version ${esc(u.tag)} is available.</b> The app downloads it, checks it, replaces this version and restarts. Your connection stays up. If the new version needs IAM policy changes, the app tells you right after.`,
      u.kind === "git" ? `<button class="btn small ghost" data-act="dismiss-update">Dismiss</button>`
        : `<button class="btn small primary" data-act="update">Update now</button><button class="btn small" data-act="releases">What's new</button><button class="btn small ghost" data-act="dismiss-update">Later</button>`));
  }
  for (const n of state.notices) {
    out.push(`<div class="banner ${n.tone}"><span class="ico">${icon(n.tone === "ok" ? "check" : "alert")}</span><div class="body">${esc(n.text)}</div><button class="btn icon ghost small" data-act="dismiss" data-id="${n.id}" aria-label="Dismiss">${icon("x", 16)}</button></div>`);
  }
  setHTML($("#banners"), out.join(""));
}

function renderHero() {
  const [headline, tone, detail] = state.status;
  $("#dot").className = "dot " + tone;
  $("#headline").textContent = headline;
  $("#detail").textContent = detail;
  const own = state.mode === "own", b = state.busy ? "disabled" : "";
  const connected = state.route?.internet?.state === "ok" || state.route?.server?.state === "ok";
  let actions;
  if (own) {
    actions = `<button class="btn primary" data-act="start" ${b}>${esc(state.startLabel)}</button>
      <button class="btn" data-act="stop" ${b}>Stop</button>
      <button class="btn icon" data-act="refresh" ${b} aria-label="Refresh">${icon("refresh", 18)}</button>`;
  } else {
    actions = (connected ? `<button class="btn primary" data-act="stop" ${b}>Disconnect</button>` : "") +
      `<button class="btn icon" data-act="refresh" ${b} aria-label="Refresh">${icon("refresh", 18)}</button>`;
  }
  setHTML($("#actions"), actions);
  const p = state.progress, prog = $("#progress");
  prog.hidden = !state.busy;
  if (state.busy) {
    $("#bar").style.transform = `scaleX(${p ? p.frac : 0.02})`;
    $("#step").textContent = p ? `${p.label}… step ${p.step} of ${p.of}, ${p.late ? "taking a little longer than usual" : `about ${p.left} left`}` : "";
  }
  $("#mode-note").textContent = own ? "Your own server, on your AWS account" : "Using a friend's server";
  $("#switch-mode").textContent = own ? "Use a friend's server instead" : "Run my own server instead";
}

function renderRoute() {
  const r = state.route;
  if (!r) return setHTML($("#route"), "");
  const deviceIcon = r.device.name === "This laptop" ? "laptop" : "desktop";
  const hop = (h, ic) => `<div class="hop ${h.state}"><div class="name">${icon(ic, 18)}<span>${esc(h.name)}</span><span class="pip" title="${esc(h.state)}"></span></div><ul>${h.lines.map((l) => `<li title="${esc(l)}">${esc(l)}</li>`).join("")}</ul></div>`;
  const wire = (a, b) => (a.state === "error" || b.state === "error" ? "error" : a.state === "busy" || b.state === "busy" ? "busy" : a.state === "ok" && b.state === "ok" ? "ok" : "idle");
  setHTML($("#route"), hop(r.device, deviceIcon) + `<div class="wire ${wire(r.device, r.server)}"></div>` +
    hop(r.server, "server") + `<div class="wire ${wire(r.server, r.internet)}"></div>` + hop(r.internet, "world"));
}

function renderTiles(sel) {
  const t = state.tiles;
  const tile = (label, value, sub, extra = "") => `<div class="tile"><span class="label">${label}</span><span class="value num">${value}</span>${extra}<span class="sub">${sub}</span></div>`;
  if (!t) return setHTML($(sel), tile("This session", "—", "Press Refresh to check") + tile("This month", "—", "") + tile("Data", "—", "") + tile("Credits left", "—", ""));
  const s = t.session, m = t.month, d = t.data;
  const session = s ? tile("This session", money(s.usd), `${hm(s.hours)} so far · ${hm(s.left_hours)} left`)
    : tile("This session", "$0.00", "No server running, nothing billing");
  const awsNote = m.aws != null ? `AWS says ${money(m.aws)}${m.forecast != null ? ` · forecast ${money(m.forecast)}` : ""}` : "Before credits · AWS figure: see Cost and data";
  const month = tile("This month", money(m.usd), awsNote);
  let data;
  if (d.used == null) data = tile("Data this month", "?", "Can't read it: update your IAM policy");
  else {
    const frac = Math.min(1, d.used / 100e9), tone = frac >= 0.95 ? "error" : frac >= 0.8 ? "warn" : "";
    data = tile("Data this month", `${gb(d.used)} <small>/ 100 GB</small>`, cap(d.reset) + (d.allow_over ? " · going over allowed" : ""),
      `<div class="meter ${tone}"><i style="transform:scaleX(${frac})"></i></div>`);
  }
  const c = t.credits;
  const credits = c ? tile("Credits left", c.unit === "USD" ? money(c.amount) : `${c.amount.toFixed(2)} ${esc(c.unit)}`, "Whole AWS account")
    : tile("Credits left", "—", "Not shown for this account");
  setHTML($(sel), session + month + data + credits);
}

function renderPlan(sel) {
  const p = state.plan;
  if (!p) return;
  const rows = p.parts.map(([name, v]) => `<span>${esc(name)}</span><span class="num">${money(v, 4)}</span>`).join("");
  setHTML($(sel), `<div class="row"><h2 class="grow" style="margin:0">What a server costs</h2><button class="btn link" data-go-to="settings">Change size or time</button></div>
    <p class="faint" style="margin:2px 0 12px">AWS list prices for ${esc(p.region_name)} (${esc(p.region)}), per hour${p.prices_date ? `, checked ${esc(p.prices_date)}` : ""}</p>
    <div class="lines">${rows}<span class="total">Total per hour</span><span class="total num">${money(p.hourly, 4)}</span></div>
    <p class="muted" style="margin:12px 0 0">It deletes itself after ${plural(p.hours, "hour")}, so a session costs at most <b class="num">${money(p.session_max)}</b>. Data is free up to 100 GB a month; beyond that AWS charges ${money(p.data_gb, 4)} per GB (only if you allow going over).</p>`);
}

function renderMonth() {
  const t = state.tiles, m = t?.month;
  setHTML($("#month-card"), `<h2>This month</h2><div class="lines">
      <span>Worked out by this app</span><span class="num">${money(m?.usd)}</span>
      <span>AWS's own figure</span><span class="num">${m?.aws != null ? money(m.aws) : "Not set up yet"}</span>
      <span>AWS's forecast for the month</span><span class="num">${m?.forecast != null ? money(m.forecast) : "—"}</span>
    </div><p class="faint" style="margin:12px 0 0">Both are before credits. AWS's figure lags by up to a day${m?.aws_at ? `; last read ${new Date(m.aws_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}` : ""}. The app's figure counts each server's running time, its public IP and disk, and data beyond 100 GB.</p>`);
  setHTML($("#aws-setup"), `<h2>See AWS's own figure (free, one time)</h2>
    <p class="muted" style="margin:0 0 10px">The app reads a free AWS Budgets budget named <code>proxy-on-demand</code> that only counts this app's servers. It creates the budget itself; AWS needs two settings once:</p>
    <ol class="muted" style="margin:0;padding-left:20px">
      <li>Billing and Cost Management → Cost allocation tags → tick <code>app</code> → Activate. It appears after your first server, and AWS takes up to a day.</li>
      <li>Update your IAM policy if the app asks (it adds read access to that one budget and to your credits).</li>
    </ol>
    <div class="row" style="margin-top:12px"><button class="btn small" data-act="link" data-link="cost_tags">Open cost allocation tags</button><button class="btn small" data-act="link" data-link="budgets">Open Budgets</button><button class="btn small" data-act="link" data-link="credits">Open Credits</button></div>`);
}

function renderJoin() {
  const own = state.mode === "own";
  const connected = state.sharing?.state === "joined";
  $("#join-card").hidden = own || connected;
  $("#join-info").hidden = own || !connected;
  $("#join-warning").textContent = state.texts.join_warning || "";
  $("#join-info-text").textContent = state.texts.join_info || "";
}

function renderSharing() {
  const s = state.sharing || {}, on = s.state === "on";
  $("#share-toggle").checked = on;
  $("#share-toggle").disabled = state.busy;
  $("#share-copy").hidden = !(on && s.server);
  $("#sharing-help").textContent = state.texts.sharing_help || "";
  let head = on ? "Sharing is on" : "Sharing is off", sub = "Only this device can use your server.";
  if (on && !s.server) sub = "Start your server to get a link. Anyone you send it to can connect while it runs.";
  else if (on && s.peers == null) sub = "Connected devices can't be listed right now (the server was started by an older version, or isn't reachable).";
  else if (on) {
    head = `Sharing is on · ${s.peers.length} of ${s.limit} devices`;
    sub = s.over ? `Over the limit of ${s.limit}: your link has probably been passed on. Press Stop and share a fresh link only with people you trust.` : "Anyone with the link can connect while this server runs. Turn sharing off or press Stop to cut everyone off.";
  }
  $("#share-head").textContent = head;
  $("#share-sub").textContent = sub;
  setHTML($("#peers"), on && s.peers ? (s.peers.length ? s.peers.map((p) => `<li><span class="num grow">${esc(p.ip)}${p.you ? " <span class=\"faint\">(you)</span>" : ""}</span><span class="faint">${plural(p.connections, "connection")}</span></li>`).join("") : `<li class="muted">Nobody is connected right now.</li>`) : "");
  const ag = $("#agreement");
  ag.hidden = !state.agreement;
  if (state.agreement) {
    setHTML(ag, `<div class="banner warn" style="margin-top:14px"><span class="ico">${icon("alert")}</span><div class="body"><b>Before you share, agree to these.</b>
      <div class="checks">${state.agreement.map((t, i) => `<label><input type="checkbox" data-agree="${i}"><span>${esc(t)}</span></label>`).join("")}</div>
      <div class="actions"><button class="btn small primary" data-act="agree" disabled>I agree, turn sharing on</button><button class="btn small ghost" data-act="agree-cancel">Cancel</button></div></div></div>`);
  }
}

// ---- settings page
async function loadSettings() {
  const s = await api().settings();
  state.settingsForm = s;
  const region = s.regions.map((r) => `<option value="${esc(r.code)}" ${r.code === s.region ? "selected" : ""}>${esc(r.name)} (${esc(r.code)})</option>`).join("");
  const size = s.sizes.map((z) => `<option value="${esc(z.code)}" ${z.code === s.size ? "selected" : ""}>${esc(z.code)}: ${esc(z.label)}</option>`).join("");
  setHTML($("#settings-form"), `
    <p class="section-title">AWS access</p>
    <div class="field"><label for="f-key">Access key ID</label><input type="text" id="f-key" spellcheck="false" autocomplete="off" placeholder="${s.key_user ? "Saved for user " + esc(s.key_user) + ". Leave empty to keep it" : "AKIA..."}"></div>
    <div class="field"><label for="f-secret">Secret access key</label><input type="password" id="f-secret" autocomplete="off" placeholder="${s.key_user ? "Leave empty to keep the saved key" : ""}"><span class="hint">Stored encrypted for your Windows account and never shown again.</span></div>
    <div class="field"><label for="f-region">Region</label><select id="f-region">${region}</select><span class="hint">Choose the one nearest to you.</span></div>
    <div class="field"><span></span><div class="row"><button class="btn small" data-act="copy-policy" data-kind="user">${icon("copy", 16)}Copy IAM policy</button><span class="faint">Then follow the steps that appear here.</span></div></div>
    <p class="section-title" style="margin-top:18px">Server</p>
    <div class="field"><label for="f-size">Size</label><select id="f-size">${size}</select></div>
    <div class="field"><label for="f-hours">Delete after</label><div class="row"><input type="number" id="f-hours" min="1" max="${s.max_hours_limit}" value="${s.max_hours}" style="width:90px"><span class="muted">hours, even if you never press Stop</span></div></div>
    <div class="field"><span></span><span class="muted num" id="f-estimate"></span></div>
    <p class="section-title" style="margin-top:18px">Data</p>
    <div class="field"><label>Free 100 GB a month</label><label class="switch"><input type="checkbox" id="f-over" ${s.allow_over ? "checked" : ""}><span>Allow going over</span></label>
      <span class="hint">Off (recommended): a server stops itself at 99.99 GB, so data never costs anything. On: no limit, data beyond 100 GB is billed.</span></div>
    <p class="section-title" style="margin-top:18px">Security</p>
    <div class="field"><label>Phone code (MFA)</label><label class="switch"><input type="checkbox" id="f-mfa" ${s.mfa ? "checked" : ""}><span>Require a code from my phone</span></label>
      <span class="hint">On: the key alone can do nothing, and AWS access lasts 1 hour, in memory only. Needs a role in AWS (README: Extra security with MFA).</span></div>
    <div class="field" id="f-mfa-tools"><span></span><div class="row"><button class="btn small" data-act="copy-policy" data-kind="trust">Copy role trust policy</button><button class="btn small" data-act="copy-policy" data-kind="role_permissions">Copy role permissions</button></div></div>
    <div class="field"><label for="f-ssm">Session Manager role</label><input type="text" id="f-ssm" value="${esc(s.ssm_role)}" spellcheck="false" placeholder="Optional"><span class="hint">An EC2 role that lets you open a shell on the server from the AWS console.</span></div>
    <div id="f-msg" class="stack" style="margin-top:10px"></div>
    <div class="row" style="margin-top:16px;justify-content:flex-end"><button class="btn primary" data-act="save-settings">Save</button></div>`);
  const update = () => { $("#f-mfa-tools").hidden = !$("#f-mfa").checked; estimate(); };
  ["#f-region", "#f-size", "#f-hours", "#f-mfa"].forEach((id) => $(id).addEventListener("input", update));
  update();
}

async function estimate() {
  const p = await api().estimate($("#f-region").value, $("#f-size").value, $("#f-hours").value);
  $("#f-estimate").textContent = `${money(p.hourly, 4)} per hour (server ${money(p.parts[0][1], 4)}, public IP ${money(p.parts[1][1], 4)}, disk ${money(p.parts[2][1], 4)}). At most ${money(p.session_max)} per session.`;
}

const form = () => ({ key_id: $("#f-key").value, secret: $("#f-secret").value, region: $("#f-region").value, size: $("#f-size").value,
  max_hours: $("#f-hours").value, allow_over: $("#f-over").checked, mfa: $("#f-mfa").checked, ssm_role: $("#f-ssm").value });

function settingsMessage(html) { setHTML($("#f-msg"), html); $("#f-msg").scrollIntoView({ block: "nearest" }); }
function guideHTML(r) {
  return banner("ok", "check", `<b>${esc(r.title)}.</b> Now, in the AWS console:<ol>${r.steps.filter(Boolean).map((s) => `<li>${esc(s.replace(/^\d+\.\s*/, ""))}</li>`).join("")}</ol>`,
    `<button class="btn small" data-act="guide" data-anchor="${esc(r.anchor)}">Step-by-step guide</button><button class="btn small" data-act="link" data-link="aws_console">Open the AWS console</button>`);
}

async function saveSettings(force = false) {
  const btn = $("[data-act=save-settings]");
  btn.disabled = true; btn.textContent = "Checking the key…";
  try {
    const r = await api().save_settings(form(), force);
    if (r.error) settingsMessage(banner("error", "alert", esc(r.error)));
    else if (r.warnings) settingsMessage(banner("warn", "alert", `<b>The key works, but:</b>${r.warnings.map((w) => `<p>${esc(w)}</p>`).join("")}`,
      `<button class="btn small" data-act="save-anyway">Save anyway</button>`));
    else { state.settingsForm = null; notify("ok", "Settings saved."); go("home"); }
  } finally { btn.disabled = false; btn.textContent = "Save"; }
}

// ---- actions
async function act(name, el) {
  const a = api();
  switch (name) {
    case "start": return a.start();
    case "stop": return a.stop();
    case "refresh": return a.refresh();
    case "dismiss": return dismiss(+el.dataset.id);
    case "update": { const tag = state.update?.tag; state.update = null; render(); return a.update_now(tag); }
    case "dismiss-update": state.update = null; return render();
    case "releases": return a.open_link("releases");
    case "link": return a.open_link(el.dataset.link);
    case "guide": return a.open_guide(el.dataset.anchor);
    case "quit-stop": state.quit = null; render(); return a.quit("stop");
    case "quit-keep": return a.quit("keep");
    case "quit-force": return a.quit("force");
    case "quit-cancel": state.quit = null; return render();
    case "mfa-ok": {
      const code = $("#mfa-code").value.trim();
      if (!/^\d{6}$/.test(code)) { $("#mfa-code").focus(); return; }
      state.mfa = false; render(); return a.mfa_code(code);
    }
    case "mfa-cancel": state.mfa = false; render(); return a.mfa_code(null);
    case "policy-copy": {
      const r = await a.copy_policy("auto");
      if (r.error) notify("warn", r.error); else state.policyGuide = r;
      return render();
    }
    case "copy-policy": {
      const r = await a.copy_policy(el.dataset.kind, form());
      return settingsMessage(r.error ? banner("error", "alert", esc(r.error)) : guideHTML(r));
    }
    case "save-settings": return saveSettings(false);
    case "save-anyway": return saveSettings(true);
    case "agree": {
      state.agreement = null;
      const r = await a.set_sharing(true, true);
      if (r.error) notify("warn", r.error);
      return render();
    }
    case "agree-cancel": state.agreement = null; $("#share-toggle").checked = false; return render();
  }
}

document.addEventListener("click", async (e) => {
  const nav = e.target.closest("[data-go]");
  if (nav) return go(nav.dataset.go);
  const to = e.target.closest("[data-go-to]");
  if (to) return go(to.dataset.goTo);
  const choice = e.target.closest("[data-choose]");
  if (choice) { const page = await api().choose(choice.dataset.choose); return go(page); }
  const el = e.target.closest("[data-act]");
  if (el && !el.disabled) act(el.dataset.act, el);
});

document.addEventListener("change", (e) => {
  if (e.target.matches("[data-agree]")) {
    $("[data-act=agree]").disabled = !$$("[data-agree]").every((c) => c.checked);
  }
});

document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target.id === "mfa-code") act("mfa-ok");
  if (e.key === "Enter" && e.target.id === "join-link") $("#join-go").click();
});

$("#share-toggle").addEventListener("change", async (e) => {
  const on = e.target.checked;
  const r = await api().set_sharing(on, false);
  if (r.agreement) { state.agreement = r.agreement; e.target.checked = false; }
  else if (r.error) { notify("warn", r.error); e.target.checked = !on; }
  render();
});
$("#share-copy").addEventListener("click", async () => {
  const r = await api().copy_share_link();
  notify(r.error ? "warn" : "ok", r.error || state.texts.share_reminder);
  render();
});
$("#join-go").addEventListener("click", async () => {
  $("#join-error").textContent = "";
  const r = await api().join($("#join-link").value);
  if (r.error) $("#join-error").textContent = r.error; else $("#join-link").value = "";
});
$("#switch-mode").addEventListener("click", async (e) => {
  const btn = e.currentTarget, confirmed = btn.dataset.confirm === "1";
  delete btn.dataset.confirm;
  const r = await api().switch_mode(confirmed);
  if (r.error) notify("warn", r.error);
  render();
  if (r.confirm) { btn.dataset.confirm = "1"; btn.textContent = r.confirm.replace(/\?$/, "") + ": click again to confirm"; }
});
$("#open-logs").addEventListener("click", () => api().open_logs());

// theme: starts from Windows' setting, the rail button flips it for this session
const dark = matchMedia("(prefers-color-scheme: dark)");
function applyTheme(isDark) {
  document.documentElement.dataset.theme = isDark ? "dark" : "light";
  $("#theme").innerHTML = (isDark ? icon("sun") : icon("moon")) + `<span class="tip">${isDark ? "Light theme" : "Dark theme"}</span>`;
  window.pywebview?.api?.set_dark(isDark);
}
$("#theme").addEventListener("click", () => applyTheme(document.documentElement.dataset.theme !== "dark"));
applyTheme(dark.matches);
drawIcons();

window.addEventListener("pywebviewready", async () => {
  const snap = await api().ready();
  Object.assign(state, { mode: snap.mode, device: snap.device, plan: snap.plan, route: snap.route, texts: snap.texts });
  state.sharing = { state: snap.settings.sharing ? "on" : "off", peers: null, limit: snap.share_limit };
  applyTheme(document.documentElement.dataset.theme === "dark");
  go(snap.screen === "choose" ? "choose" : "home");
});
