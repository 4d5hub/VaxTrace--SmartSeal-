(function () {
"use strict";
const q = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cut = (h, n = 10) => h ? esc(String(h).slice(0, n)) + "…" : "—";
const hx = h => h ? `<code title="${esc(h)}" onclick="navigator.clipboard&&navigator.clipboard.writeText(this.title)">${cut(h)}</code>` : "—";
const TABS = ["Hardware", "Records", "Cryptographic evidence", "Custody", "Blockchain", "Attacks", "Destination verifier", "India case study"];
const LV = { mode: "sim", tab: 0, ship: null, batch: null, timer: null, last: "", busy: false, msg: {} };
const D = {};
let indiaHome = null;

const base = () => q("lvUrl").value.replace(/\/+$/, "");
async function api(path, o = {}) {
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), o.timeout || 9000);
  try {
    const r = await fetch(base() + path, { method: o.method || "GET", signal: ctl.signal,
      headers: { "Content-Type": "application/json", "X-API-Key": q("lvKey").value }, body: o.body ? JSON.stringify(o.body) : undefined });
    const json = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, json };
  } catch (e) {
    return { ok: false, status: 0, json: { error: { code: "UNREACHABLE", message: String((e && e.message) || e) } } };
  } finally { clearTimeout(t); }
}
const errOf = r => (r && r.json && r.json.error) || { code: "ERROR", message: "request failed" };
const errBox = (r, what) => `<div class="err"><b>${esc(what)}:</b> ${esc(errOf(r).code)}: ${esc(errOf(r).message)}</div>`;
const ship = () => (D.ships || []).find(s => s.shipmentId === LV.ship);
const enc = () => encodeURIComponent(LV.ship || "");

const LOAD = {
  rec: async () => D.rec = await api(`/api/records?shipmentId=${enc()}&limit=1000`),
  queue: async () => D.queue = await api("/api/queue"),
  batches: async () => { D.batches = await api(`/api/batches?shipmentId=${enc()}`);
    const list = (D.batches.json && D.batches.json.batches) || [];
    if (list.length) { const id = list.some(b => b.batchId === LV.batch) ? LV.batch : list[list.length - 1].batchId; LV.batch = id;
      D.batchDetail = await api(`/api/batches/${id}?shipmentId=${enc()}`); } else D.batchDetail = null; },
  verify: async () => D.verify = await api(`/api/verify-chain?shipmentId=${enc()}`),
  tamper: async () => D.tamper = await api(`/api/tamper-events?shipmentId=${enc()}`),
  custody: async () => D.custody = await api(`/api/custody?shipmentId=${enc()}`),
  bcStatus: async () => D.bcStatus = await api("/api/blockchain/status", { timeout: 15000 }),
  blocks: async () => D.blocks = await api("/api/blockchain/blocks?limit=8"),
  bcShip: async () => D.bcShip = await api(`/api/blockchain/shipments/${enc()}`),
  bcBatches: async () => D.bcBatches = await api(`/api/blockchain/batches/${enc()}`),
  vres: async () => D.vres = await api(`/api/verifier/result?shipmentId=${enc()}`),
  attacks: async () => D.attacks = await api("/api/attacks"),
};
const NEED = [["rec", "queue"], ["rec"], ["rec", "batches", "verify", "tamper"], ["custody"], ["bcStatus", "blocks", "bcShip", "bcBatches", "queue"], ["attacks"], ["vres", "bcShip"], []];

async function ping() {
  const r = await api("/api/health", { timeout: 4000 });
  const c = q("lvConn");
  c.className = "conn " + (r.ok ? "up" : "down");
  c.textContent = "LIVE BACKEND: " + (r.ok ? "CONNECTED" : "DISCONNECTED");
  return r.ok;
}

async function refresh(force) {
  if (LV.mode !== "live" || LV.busy) return;
  LV.busy = true;
  try {
    if (!(await ping())) { D.offline = true; return draw(true); }
    D.offline = false;
    const [st, sh, se] = await Promise.all([api("/api/status"), api("/api/shipments"), api("/api/seals")]);
    D.status = st.json; D.ships = Array.isArray(sh.json) ? sh.json : []; D.seals = Array.isArray(se.json) ? se.json : [];
    if (!LV.ship || !ship()) LV.ship = D.ships.length ? D.ships[D.ships.length - 1].shipmentId : null;
    const sel = q("lvShip");
    sel.innerHTML = D.ships.map(s => `<option ${s.shipmentId === LV.ship ? "selected" : ""}>${esc(s.shipmentId)}</option>`).join("") || "<option>(none)</option>";
    if (LV.ship) { for (const k of NEED[LV.tab]) await LOAD[k](); }
    draw(force);
  } finally { LV.busy = false; }
}

const tag = s => `<span class="st ${esc(s)}">${esc(s)}</span>`;
const when = t => t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19) : "—";
const noShip = () => '<div class="info">No shipment exists yet. Create one with <code>python integration\\live_demo.py seed</code> (see the README), then press Refresh.</div>';

function tHardware() {
  const recs = (D.rec && D.rec.json && D.rec.json.records) || [], last = recs[recs.length - 1];
  const sh = ship(), pol = (sh && sh.policy) || { tempMinC: 2, tempMaxC: 8, shockLimitG: 2.5 };
  const seal = (D.seals || []).find(s => sh && s.sealId === sh.sealId) || {};
  const pend = D.queue && D.queue.json ? D.queue.json.pending : "?";
  const hot = last && (last.temperature1 < pol.tempMinC || last.temperature1 > pol.tempMaxC || last.temperature2 < pol.tempMinC || last.temperature2 > pol.tempMaxC);
  const red = last && (last.lid || last.shock > pol.shockLimitG || seal.revoked), amber = hot || pend > 0 || !(D.status && D.status.ledger && D.status.ledger.available);
  const oled = last ? `${seal.sealId || "SEAL"}  rec#${last.seq}\nT1 ${last.temperature1.toFixed(1)}C  T2 ${last.temperature2.toFixed(1)}C\nSHOCK ${last.shock.toFixed(1)}g LID:${last.lid ? "OPEN" : "SHUT"} LIGHT:${last.light ? "ON" : "OFF"}\nCHAIN:${D.status && D.status.ledger && D.status.ledger.available ? "OK" : "DOWN"} Q:${pend}${seal.revoked ? "  REVOKED" : ""}` : "no records yet";
  return `<div class="two"><div><h4>Smart seal</h4><div class="oled">${esc(oled)}</div>
<div><span class="led ${!hot && !red ? "g" : ""}"></span><span class="led ${amber ? "a" : ""}"></span><span class="led ${red ? "r" : ""}"></span><span class="m">${red ? "buzzer sounding" : "buzzer quiet"}</span></div>
<h4>Latest sensor record</h4>${last ? `<div class="kv"><span>record</span><span>#${last.seq}, ${esc(last.timestamp)}</span><span>temperature 1 (primary)</span><span>${last.temperature1.toFixed(2)} °C</span><span>temperature 2 (audit probe)</span><span>${last.temperature2.toFixed(2)} °C</span><span>shock</span><span>${last.shock.toFixed(2)} g</span><span>lid</span><span>${last.lid ? "OPEN" : "closed"}</span><span>light</span><span>${last.light ? "light detected" : "dark"}</span></div>` : '<p class="m">No records received yet.</p>'}</div>
<div><h4>Secure identity and device status</h4><div class="kv"><span>seal</span><span>${esc(seal.sealId || "—")}</span><span>public key</span><span>${hx(seal.publicKey)}</span>
<span>key provisioning</span><span>${seal.provisioning === "MOCK_SECURE_ELEMENT" ? "software stand-in for the secure element (not a real ATECC608)" : esc(seal.provisioning || "—")}</span>
<span>last accepted counter</span><span>${esc(seal.lastCounter ?? "—")}</span><span>revoked</span><span>${seal.revoked ? '<span class="bad">yes</span>' : "no"}</span>
<span>records stored</span><span>${recs.length}</span><span>batch size</span><span>${esc(D.status && D.status.batchSize)}</span>
<span>commitments waiting for the ledger</span><span>${esc(pend)}</span><span>ledger</span><span>${D.status && D.status.ledger ? esc(D.status.ledger.mode || "") + (D.status.ledger.available ? " (reachable)" : " (not reachable: commitments queue locally)") : "—"}</span></div>
<div class="info">Sensor readings come from the Wokwi ESP32 (or the stand-in script). The page shows what the gateway stored; it does not read hardware directly.</div></div></div>`;
}

function tRecords() {
  const r = (D.rec && D.rec.json && D.rec.json.records) || [];
  if (D.rec && !D.rec.ok) return errBox(D.rec, "Records");
  return `<h4>Raw off-chain records (${r.length}), newest first</h4><div class="scrollx"><table><tr><th>seq<th>timestamp<th>T1 °C<th>T2 °C<th>shock g<th>lid<th>light<th>prevHash<th>hash</tr>` +
    r.slice(-60).reverse().map(x => `<tr><td>${x.seq}<td>${esc(x.timestamp)}<td>${x.temperature1.toFixed(2)}<td>${x.temperature2.toFixed(2)}<td>${x.shock.toFixed(2)}<td>${x.lid ? "OPEN" : "·"}<td>${x.light ? "ON" : "·"}<td>${hx(x.prevHash)}<td>${hx(x.hash)}</tr>`).join("") + "</table></div>" +
    '<p class="m">Each record hashes the previous one. Changing any stored value breaks the chain from that point on.</p>';
}

function tEvidence() {
  const v = D.verify && D.verify.json, b = (D.batches && D.batches.json && D.batches.json.batches) || [], det = D.batchDetail && D.batchDetail.json, tam = (D.tamper && D.tamper.json && D.tamper.json.events) || [];
  let h = "<h4>Integrity checks</h4>";
  h += v && v.checks ? `<p class="m" style="margin:0 0 6px">${esc(v.scope)}</p>` + v.checks.map(c => `<div>${tag(c.status)} ${esc(c.name)} <span class="m">${esc(c.detail)}</span></div>`).join("") : errBox(D.verify, "Integrity check");
  h += `<h4>Batches (${b.length})</h4><div class="scrollx"><table><tr><th>batch<th>seq range<th>count<th>Merkle root<th>prevRoot<th>counter<th>signature<th>ledger</tr>` +
    b.map(x => `<tr><td>${x.batchId}<td>${x.firstSeq}–${x.lastSeq}<td>${x.count}<td>${hx(x.root)}<td>${hx(x.prevRoot)}<td>${x.counter}<td>${hx(x.signature)}<td>${tag(x.anchorStatus)} ${hx(x.anchorTx)}</tr>`).join("") + "</table></div>";
  h += `<p class="m">Counters in use: ${esc([...b.map(x => x.counter), ...tam.map(t => t.counter)].sort((a, c) => a - c).join(", ") || "none")}. They must be contiguous; a hole means something was signed that never reached the ledger.</p>`;
  if (det && det.merkle) {
    const lv = det.merkle.levels;
    h += `<h4>Merkle tree, batch <select id="lvBatchSel">${b.map(x => `<option ${x.batchId === LV.batch ? "selected" : ""}>${x.batchId}</option>`).join("")}</select></h4><div class="tree">` +
      lv.map((row, i) => `<div class="row">${row.map((n, j) => `<span class="n ${i === lv.length - 1 ? "root" : ""}" title="${esc(n)}">${i === 0 ? "#" + det.records[j].seq + " " : ""}${cut(n, 8)}</span>`).join("")}</div>`).reverse().join("") + "</div>";
  }
  h += `<h4>Signed tamper events (${tam.length})</h4>` + (tam.length ? "<table><tr><th>type<th>record<th>counter<th>ledger</tr>" + tam.map(t => `<tr><td>${esc(t.eventType)}<td>${t.seq}<td>${t.counter}<td>${tag(t.anchorStatus)}</tr>`).join("") + "</table>" : '<p class="m">none</p>');
  return h;
}

function tCustody() {
  const c = D.custody && D.custody.json;
  if (!c || !c.route) return errBox(D.custody, "Custody");
  const done = c.handoffs.length;
  let h = `<h4>Route</h4><div class="route">${c.route.map((p, i) => `<span class="party ${i < done ? "done" : ""} ${i === Math.min(done, 3) && !c.complete ? "holder" : ""}">${esc(p)}</span>${i < 3 ? "<span>→</span>" : ""}`).join("")}</div>
<div class="kv"><span>current holder</span><span>${c.complete ? "PHARMACY (custody complete)" : esc(c.currentCustodianRole)}</span><span>handoffs completed</span><span>${done} of 3</span></div>
<h4>Dual-signed handoffs</h4>` + (done ? `<div class="scrollx"><table><tr><th>from<th>to<th>nonce<th>at record<th>timestamp<th>sender sig<th>receiver sig<th>ledger</tr>` +
    c.handoffs.map(x => `<tr><td>${esc(x.fromRole)}<td>${esc(x.toRole)}<td>${hx(x.nonce)}<td>${x.atSeq}<td>${esc(x.timestamp)}<td>${x.sigFrom ? '<span class="st yes">signed</span>' : '<span class="st no">missing</span>'}<td>${x.sigTo ? '<span class="st yes">signed</span>' : '<span class="st no">missing</span>'}<td>${tag(x.anchorStatus)} ${hx(x.anchorTx)}</tr>`).join("") + "</table></div>" : '<p class="m">No handoff yet.</p>');
  h += `<h4>Try a handoff (demo keys)</h4><p class="m" style="margin:0 0 6px">The gateway signs for the parties with public demo keys so each rejection can be shown. In a real deployment each party signs on its own device.</p>
<div><button data-h="both">Both parties sign</button> <button data-h="sender_only">Only the sender signs</button> <button data-h="receiver_only">Only the receiver signs</button> <button data-h="reuse_nonce">Reuse an old nonce</button> <button data-h="wrong_receiver_signer">Someone else signs for the receiver</button></div>
<div class="lvmsg" id="lvCustMsg">${LV.msg.cust || ""}</div><p class="m">A nonce is a one-time value in each handoff. Once used it can never be used again, so an old approval cannot be replayed.</p>`;
  return h;
}

function tBlockchain() {
  const s = D.bcStatus && D.bcStatus.json, bl = D.blocks && D.blocks.json, sh = D.bcShip && D.bcShip.json, bb = D.bcBatches && D.bcBatches.json, qu = D.queue && D.queue.json;
  let h = "";
  if (D.bcStatus && !D.bcStatus.ok) h += errBox(D.bcStatus, "Blockchain status");
  const qb = s && s.qbft;
  if (qb) h += `<h4>Validators (measured, not simulated)</h4><div class="scrollx"><table><tr><th>validator<th>JSON-RPC<th>reachable<th>block<th>peers</tr>` +
    qb.nodes.map(n => `<tr><td>${esc(n.name)}<td>${esc(n.rpc)}<td>${n.reachable ? '<span class="st yes">yes</span>' : '<span class="st no">no</span>'}<td>${esc(n.blockNumber ?? "—")}<td>${esc(n.peerCount ?? "—")}</tr>`).join("") + "</table></div>" +
    `<div class="${qb.canCommit ? "info" : "err"}"><b>Quorum:</b> ${qb.reachable} of ${qb.validatorCount} validators reachable. QBFT needs ${qb.quorumRequired}. ${qb.canCommit ? "Commits are possible." : "No quorum: new transactions cannot be committed, so commitments wait in the local queue."}<br><span class="m">${esc(qb.note)}</span></div>`;
  if (s && s.deployment) h += `<div class="kv"><span>chain id</span><span>${esc(s.deployment.chainId)}</span><span>registry</span><span>${hx(s.deployment.contracts.registry)}</span><span>batch anchor</span><span>${hx(s.deployment.contracts.anchor)}</span><span>custody</span><span>${hx(s.deployment.contracts.custody)}</span><span>verdicts</span><span>${hx(s.deployment.contracts.verdict)}</span></div>`;
  h += "<h4>Latest blocks</h4>";
  h += bl && bl.blocks ? `<div class="scrollx"><table><tr><th>block<th>time (UTC)<th>proposer<th>commit seals<th>transactions</tr>` +
    bl.blocks.map(b => `<tr><td>${b.number}<td>${when(b.timestamp)}<td>${hx(b.proposer)}<td>${esc(b.commitSeals ?? "n/a")}<td class="wrapcell">${b.transactions.length ? b.transactions.map(t => `${hx(t.hash, 8)} <span class="m">${esc(t.fromRole || "")}</span>`).join("<br>") : "—"}</tr>`).join("") + "</table></div>" : errBox(D.blocks, "Blocks");
  h += "<h4>This shipment on-chain</h4>";
  h += sh && sh.shipment ? `<div class="kv"><span>shipment</span><span>${esc(sh.shipment.shipmentId)} (${sh.shipment.active ? "active" : "closed"})</span><span>seal</span><span>${esc(sh.shipment.sealId)}${sh.seal && sh.seal.revoked ? ' <b class="bad">REVOKED</b>' : ""}</span><span>policy hash</span><span>${hx(sh.shipment.policyHash)}</span><span>anchored batches</span><span>${sh.batchCount}</span><span>tamper events</span><span>${sh.tamperCount}</span><span>custody handoffs</span><span>${sh.handoffCount}</span><span>last counter</span><span>${sh.lastCounter}</span><span>final verdict</span><span>${sh.verdict ? `<b>${esc(sh.verdict.verdict)}</b> ${esc(sh.verdict.reasonCodes.join(", "))}` : "not finalized yet"}</span></div>` : errBox(D.bcShip, "Shipment on-chain");
  if (bb && bb.batches) h += `<h4>Batch anchors on the ledger</h4><div class="scrollx"><table><tr><th>batch<th>records<th>Merkle root<th>counter<th>anchored at (UTC)</tr>` + bb.batches.map(b => `<tr><td>${b.batchId}<td>${b.firstSeq}–${b.lastSeq}<td>${hx(b.root)}<td>${b.counter}<td>${when(b.anchoredAt)}</tr>`).join("") + "</table></div>";
  if (qu) h += `<h4>Commitment queue</h4><p>${qu.pending} waiting for the ledger.</p>` + (qu.items.length ? "<table><tr><th>#<th>kind<th>status<th>attempts<th>reason<th>tx</tr>" + qu.items.slice(0, 8).map(i => `<tr><td>${i.id}<td>${esc(i.kind)}<td>${tag(i.status)}<td>${i.attempts}<td>${esc(i.error_code || "")}<td>${hx(i.tx_hash)}</tr>`).join("") + "</table>" : "");
  return h;
}

function tAttacks() {
  const a = D.attacks && D.attacks.json;
  if (!a) return errBox(D.attacks, "Attack results");
  const rep = a.report;
  let h = `<div><button id="lvAtkRun" ${a.running ? "disabled" : ""}>${a.running ? "Running the 16 scenarios…" : "Run the attack suite"}</button> <span class="m">Each scenario runs on its own fresh in-memory chain and database, so your live data is never touched.</span></div>`;
  if (a.error) h += `<div class="err">${esc(a.error)}</div>`;
  if (!rep) return h + '<p class="m">No report yet. Press the button (takes about a minute).</p>';
  h += `<div class="info"><b>${rep.summary.pass} passed, ${rep.summary.fail} failed, ${rep.summary.skipped} skipped</b> of ${rep.summary.total}. Mode: ${esc(rep.mode)}. Generated ${esc(rep.generatedAt)}.</div>
<div class="scrollx"><table><tr><th>#<th>attack<th>class<th>expected<th>actual<th>what caught it<th>limitation<th>result</tr>` +
    rep.results.map(r => { const o = r.observed || {}; const actual = o.skipped ? esc(o.reason) : esc([o.verdict && o.verdict !== "n/a" ? o.verdict : "", (o.codes || []).join(", "), o.revert || o.contract_revert || o.error || ""].filter(Boolean).join("  "));
      return `<tr><td>${r.id}<td class="wrapcell"><b>${esc(r.name)}</b><br><span class="m">${esc(r.attackerAction)}</span><td>${tag(r.classification)}<td class="wrapcell">${esc(r.expected)}<td class="wrapcell">${actual}<td class="wrapcell">${esc(r.detection)}<td class="wrapcell">${esc(r.limitation)}<td>${tag(r.status)}</tr>`; }).join("") + "</table></div>";
  h += "<h4>What remains unsolved</h4><table><tr><th>limitation<th>status<th>note</tr>" + rep.limitations.map(l => `<tr><td class="wrapcell">${esc(l.item)}<td>${tag(l.classification)}<td class="wrapcell">${esc(l.note)}</tr>`).join("") + "</table>";
  return h + `<p class="m">${esc(rep.disclaimer)}</p>`;
}

function tVerifier() {
  const v = D.vres && D.vres.json, sh = D.bcShip && D.bcShip.json;
  let h = `<div><button id="lvVer">Run verification</button> <button id="lvVerFin" title="Also writes the verdict to the blockchain and closes the shipment">Run and finalize on-chain</button> <span class="m">The verifier reads the chain and the raw evidence separately; it does not use the gateway's database.</span></div><div class="lvmsg">${LV.msg.ver || ""}</div>`;
  if (!v || !v.verdict) return h + `<p class="m">${D.vres && D.vres.status === 404 ? "No verification has been run for this shipment yet." : ""}</p>` + (D.vres && !D.vres.ok && D.vres.status !== 404 ? errBox(D.vres, "Verifier") : "");
  h += `<div class="verdict ${esc(v.verdict)}">${esc(v.verdict)}</div>`;
  h += v.codes.length ? "<h4>Reasons</h4>" + v.codes.map((c, i) => `<div><code>${esc(c)}</code> ${esc(v.reasons[i])}</div>`).join("") : '<p class="m">All checks passed: no reasons to list.</p>';
  h += `<h4>Checks (${v.checks.length})</h4>` + v.checks.map(c => `<div>${tag(c.status)} <span class="m">${c.step}</span> ${esc(c.name)} <span class="m">${esc(c.detail)}</span></div>`).join("");
  h += `<p class="m">Verified in ${esc(v.elapsedMs)} ms. Report hash ${hx(v.reportHash)}. ${esc(v.policyNote || "")}</p>`;
  if (v.finalized) h += `<div class="info">Finalization: ${esc(v.finalized.status)} ${v.finalized.txHash ? hx(v.finalized.txHash) : esc(v.finalized.error || "")}</div>`;
  if (sh && sh.verdict) h += `<div class="info"><b>On-chain verdict:</b> ${esc(sh.verdict.verdict)} ${esc(sh.verdict.reasonCodes.join(", "))} (issued by ${esc(sh.verdict.verifierRole || "—")})</div>`;
  return h;
}

const RENDER = [tHardware, tRecords, tEvidence, tCustody, tBlockchain, tAttacks, tVerifier, null];

function draw(force) {
  const body = q("lvBody"), ind = q("lvIndia");
  q("lvTabs").querySelectorAll("button").forEach((b, i) => { b.className = i === LV.tab ? "on" : ""; b.setAttribute("aria-selected", i === LV.tab); });
  if (LV.tab === 7) { body.hidden = true; ind.hidden = false; mountIndia(); return; }
  unmountIndia(); body.hidden = false; ind.hidden = true;
  if (D.offline) {
    body.innerHTML = `<div class="err"><b>Live backend is not reachable at ${esc(base())}.</b> Start it with <code>demo.bat</code> (real Besu network) or <code>python integration\\serve_stack.py</code> (no Docker), then press Refresh. Simulation mode still works.</div>`;
    return;
  }
  if (!LV.ship && LV.tab !== 4 && LV.tab !== 5) { body.innerHTML = noShip(); return; }
  const html = RENDER[LV.tab]();
  const sig = LV.tab + "|" + html;
  if (!force && sig === LV.last) return;
  LV.last = sig; body.innerHTML = html; wire();
}

function mountIndia() { const n = q("india"); if (n && n.parentNode !== q("lvIndia")) { indiaHome = { p: n.parentNode, n: n.nextSibling }; q("lvIndia").appendChild(n); } }
function unmountIndia() { const n = q("india"); if (n && indiaHome && n.parentNode === q("lvIndia")) { indiaHome.p.insertBefore(n, indiaHome.n); } }

function wire() {
  const body = q("lvBody");
  body.querySelectorAll("[data-h]").forEach(b => b.onclick = async () => {
    const stage = (D.custody.json.handoffs || []).length, route = D.custody.json.route;
    if (stage >= 3 && b.dataset.h !== "reuse_nonce") { LV.msg.cust = '<span class="bad">ROUTE_COMPLETE: custody already reached the pharmacy.</span>'; return refresh(true); }
    const r = await api("/api/custody/demo-handoff", { method: "POST", body: { shipmentId: LV.ship, fromRole: route[Math.min(stage, 2)], toRole: route[Math.min(stage, 2) + 1], mode: b.dataset.h } });
    LV.msg.cust = r.ok ? '<span class="ok">Accepted: both signatures verified and queued for the ledger.</span>' : `<span class="bad">Rejected: <b>${esc(errOf(r).code)}</b> ${esc(errOf(r).message)}</span>`;
    refresh(true);
  });
  const sel = q("lvBatchSel"); if (sel) sel.onchange = () => { LV.batch = +sel.value; refresh(true); };
  const run = q("lvAtkRun"); if (run) run.onclick = async () => { const r = await api("/api/attacks/run", { method: "POST" }); if (!r.ok) alert(errOf(r).code + ": " + errOf(r).message); refresh(true); };
  const go = async fin => { LV.msg.ver = "Running the 25 checks…"; draw(true); const r = await api(`/api/verifier/run?shipmentId=${enc()}&finalize=${fin}`, { method: "POST", timeout: 120000 });
    LV.msg.ver = r.ok ? "" : `<span class="bad">${esc(errOf(r).code)}: ${esc(errOf(r).message)}</span>`; refresh(true); };
  if (q("lvVer")) q("lvVer").onclick = () => go(false);
  if (q("lvVerFin")) q("lvVerFin").onclick = () => go(true);
}

function download(name, text, type) { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; document.body.appendChild(a); a.click(); a.remove(); }
async function exportAudit() {
  if (!LV.ship) return alert("No shipment selected.");
  const get = async p => (await api(p)).json;
  const [bundle, verify, custody, bcShip, bcBatches, bcCustody, valid, vres, att, status] = await Promise.all([
    get(`/api/export?shipmentId=${enc()}`), get(`/api/verify-chain?shipmentId=${enc()}`), get(`/api/custody?shipmentId=${enc()}`), get(`/api/blockchain/shipments/${enc()}`),
    get(`/api/blockchain/batches/${enc()}`), get(`/api/blockchain/custody/${enc()}`), get("/api/blockchain/validators"), get(`/api/verifier/result?shipmentId=${enc()}`), get("/api/attacks"), get("/api/status")]);
  const b = bundle.bundle || {};
  const report = {
    project: "Tamper-evident smart seal for multi-party custody of critical goods", generatedAt: new Date().toISOString(), gateway: base(),
    sealId: b.seal && b.seal.sealId, shipmentId: LV.ship, records: b.records, hashChainStatus: verify.checks, batches: b.batches,
    merkleRoots: (b.batches || []).map(x => ({ batchId: x.batchId, root: x.root, prevRoot: x.prevRoot })),
    signatures: (b.batches || []).map(x => ({ batchId: x.batchId, signature: x.signature, counter: x.counter })), counters: [...(b.batches || []), ...(b.tamperEvents || [])].map(x => x.counter).sort((x, y) => x - y),
    custody: custody.handoffs, tamperEvents: b.tamperEvents,
    blockchainReferences: { contracts: status.chain, shipment: bcShip, batchesOnChain: bcBatches, custodyOnChain: bcCustody, anchorTransactions: (b.batches || []).map(x => ({ batchId: x.batchId, status: x.anchorStatus, tx: x.anchorTx })) },
    validatorState: valid, verification: vres && vres.checks ? { checks: vres.checks, elapsedMs: vres.elapsedMs, reportHash: vres.reportHash } : "no verifier result yet",
    verdict: vres && vres.verdict, reasonCodes: vres && vres.codes, policy: b.shipment && b.shipment.policy, policyNote: status.policyDisclaimer,
    limitations: (att.report && att.report.limitations) || "run the attack suite to include the limitation table", attackSuite: att.report ? att.report.summary : null,
    honesty: "Tamper-evident and cryptographically verifiable. Not tamper-proof. The mock secure element is a software stand-in; sensors are simulated unless real hardware is attached." };
  download("audit-report.json", JSON.stringify(report, null, 2), "application/json");
  const t = (rows, cols) => "<table border=1 cellpadding=4 style='border-collapse:collapse;font-size:12px'><tr>" + cols.map(c => `<th>${esc(c)}`).join("") + "</tr>" + rows.map(r => "<tr>" + cols.map(c => `<td>${esc(r[c] ?? "")}`).join("") + "</tr>").join("") + "</table>";
  download("audit-report.html", `<!DOCTYPE html><meta charset=utf-8><title>Audit report ${esc(LV.ship)}</title><body style="font:14px Georgia,serif;max-width:980px;margin:24px auto">
<h1>Audit report: ${esc(LV.ship)}</h1><p>Generated ${esc(report.generatedAt)}. Seal ${esc(report.sealId)}.</p><h2>Verdict: ${esc(report.verdict || "not verified yet")}</h2><p>${esc((report.reasonCodes || []).join(", "))}</p>
<h3>Verification checks</h3>${vres && vres.checks ? t(vres.checks, ["step", "name", "status", "detail"]) : "<p>none</p>"}
<h3>Batches</h3>${t(b.batches || [], ["batchId", "firstSeq", "lastSeq", "count", "root", "counter", "anchorStatus", "anchorTx"])}
<h3>Custody</h3>${t(custody.handoffs || [], ["fromRole", "toRole", "nonce", "atSeq", "anchorStatus"])}
<h3>Limitations</h3>${Array.isArray(report.limitations) ? t(report.limitations, ["item", "classification", "note"]) : "<p>" + esc(report.limitations) + "</p>"}
<p><i>${esc(report.honesty)}</i></p></body>`, "text/html");
}

function setMode(m) {
  LV.mode = m;
  q("simRoot").hidden = m === "live"; q("liveRoot").hidden = m !== "live"; q("liveCfg").hidden = m !== "live";
  q("mSim").className = m === "sim" ? "on" : ""; q("mLive").className = m === "live" ? "on" : "";
  clearInterval(LV.timer); LV.timer = null;
  if (m === "live") {
    try { if (typeof timer !== "undefined" && timer) setRun(false); } catch (e) { }
    LV.timer = setInterval(() => refresh(false), 4000); refresh(true);
  } else {
    unmountIndia();
    const c = q("lvConn"); c.className = "conn unk"; c.textContent = "LIVE BACKEND: NOT CHECKED";
    try { if (typeof setRun === "function") setRun(true); } catch (e) { }
  }
}
q("lvTabs").innerHTML = TABS.map((t, i) => `<button role="tab" data-t="${i}">${esc(t)}</button>`).join("");
q("lvTabs").onclick = e => { const i = e.target.dataset && e.target.dataset.t; if (i != null) { LV.tab = +i; LV.last = ""; draw(true); refresh(true); } };
q("mSim").onclick = () => setMode("sim"); q("mLive").onclick = () => setMode("live");
q("lvRefresh").onclick = () => refresh(true); q("lvExport").onclick = exportAudit;
q("lvShip").onchange = e => { LV.ship = e.target.value; LV.batch = null; refresh(true); };
q("lvUrl").onchange = () => refresh(true); q("lvKey").onchange = () => refresh(true);
window.SmartSealLive = { setMode, refresh, state: LV, data: D };
})();
