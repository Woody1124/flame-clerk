// The clerk: reads payments to the owner's address, and inscribes a BLACKBODY child for each one, with the parent as the
// first input of the reveal. One run does one batch and exits; run it every few minutes.
//   QBIT_SEED="..." node clerk.mjs run [--send] [--free N]   (without --send: show the plan, change nothing; --free N mints N unpaid
//                                                            flames to FREE_TO or the owner: a rehearsal, never run by the schedule)
//   node clerk.mjs status                            (no seed needed: what is paid, what is minted, what is waiting)
//
// Config (env):  PARENT, LIB, OWNER (the sales address that receives the payments), PRICE (bits), CAP,
//                START, END (the sale window, blocks, payments counted by their confirming block), RATE (bits per explorer vB),
//                BATCH (children per transaction, default 20), CONFS (confirmations required, default 2),
//                SWEEP=1 (after END, mint what is left to OWNER so the collection is whole), QBIT_API, QORD_URL
//
// The chain is the only state: a payment is "done" when a child of the parent carries its txid in its metadata.
import { net, api, qord, log, qbt, sleep, P, walletFromSeed, floatCoins, planBatch, buildBatch, pushWithRetry, broadcast, hex, cborDecode, POSTAGE } from "./chain.mjs";

const env = process.env;
export const cfgFromEnv = () => ({
  parent: env.PARENT, lib: env.LIB, owner: env.OWNER, price: BigInt(env.PRICE || "500000000"), cap: +(env.CAP || 1024),
  start: +(env.START || 0), end: +(env.END || 1e12), rate: +(env.RATE || 5), batch: +(env.BATCH || 20), confs: +(env.CONFS || 2), sweep: env.SWEEP === "1",
});

// the page the child inscription carries: it loads the library and shows itself
export const childHtml = (parent, lib) =>
  `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>BLACKBODY</title><body style="margin:0;background:#000;overflow:hidden"><script src="/content/${lib}"></script><script>BB.child("${parent}")</script>`;

async function allPages(path) { const ids = []; for (let p = 0; ; p++) { const r = await qord(`${path}/${p}`); ids.push(...r.ids); if (!r.more) break; } return ids; }

// Where the parent is now. The viewer may lag a block behind; follow spends in the explorer (the parent always returns to output 0).
export async function locateParent(parentId) {
  const j = await qord(`/r/inscription/${parentId}`);
  let [txid, vout] = j.output.split(":"); vout = +vout;
  for (let hops = 0; hops < 50; hops++) {
    const o = (await api(`/tx/${txid}/outspends`))[vout]; // one entry per output
    if (!o || !o.spent) break;
    txid = o.txid; vout = 0; // our own reveal: parent comes back on output 0
  }
  const t = await api(`/tx/${txid}`);
  return { id: parentId, txid, vout, value: t.vout[vout].value, confirmed: t.status?.confirmed === true, height: t.status?.block_height };
}

// Every confirmed payment of at least the price to the owner, oldest first, with who paid.
export async function readPayments(cfg, tip) {
  const out = []; let last = null;
  for (let page = 0; page < 400; page++) {
    const txs = await api(`/address/${cfg.owner}/txs${last ? "?after_txid=" + last : ""}`); // the Qbit explorer pages by after_txid, newest first
    if (!Array.isArray(txs) || !txs.length) break;
    let older = false, sawConfirmed = false;
    for (const t of txs) {
      if (!t.status?.confirmed) continue;
      last = t.txid; sawConfirmed = true;
      const h = t.status.block_height;
      if (h < cfg.start) { older = true; continue; }
      if (h > cfg.end || tip - h + 1 < cfg.confs) continue; // outside the sale, or not deep enough yet
      const paid = t.vout.filter((o) => o.scriptpubkey_address === cfg.owner).reduce((s, o) => s + BigInt(o.value), 0n);
      if (paid < cfg.price) continue;
      const sender = t.vin.find((i) => i.prevout?.scriptpubkey_address)?.prevout.scriptpubkey_address;
      if (!sender || t.vin.every((i) => i.prevout?.scriptpubkey_address === cfg.owner)) { if (!process.env.ALLOW_SELF) continue; }
      // the buyer may name another address for the flame: memo "BB1|<address>"
      let to = sender;
      for (const o of t.vout) {
        if (o.scriptpubkey_type !== "op_return" && !o.scriptpubkey?.startsWith("6a")) continue;
        const m = /BB1\|(qb1z[0-9a-z]+)/.exec(Buffer.from(o.scriptpubkey, "hex").toString("latin1"));
        if (m) { try { P.decodeP2mrAddress(m[1], net.network); to = m[1]; } catch { /* a bad address in the memo: keep the sender */ } }
      }
      out.push({ txid: t.txid, height: h, to, paid });
    }
    if (older || !sawConfirmed) break;
  }
  return out.sort((a, b) => a.height - b.height || (a.txid < b.txid ? -1 : 1));
}

async function mapLimit(items, n, f) { const out = new Array(items.length); let i = 0; await Promise.all(Array.from({ length: n }, async () => { while (i < items.length) { const k = i++; out[k] = await f(items[k], k); } })); return out; }

export async function survey(cfg) {
  const tip = +(await api("/blocks/tip/height"));
  const viewer = await qord("/status");
  const kids = await allPages(`/r/children/${cfg.parent}`);
  const metas = await mapLimit(kids, 8, async (id) => { try { const h = await qord(`/r/metadata/${id}`); return h ? cborDecode(Buffer.from(h, "hex")) : null; } catch { return null; } });
  const done = new Set(metas.filter((m) => m && m.pay).map((m) => m.pay));
  const payments = await readPayments(cfg, tip);
  const pending = payments.filter((p) => !done.has(p.txid));
  return { tip, viewerHeight: viewer.height, kids, metas, done, payments, pending };
}

export async function run({ send, free = 0 }) {
  const cfg = cfgFromEnv();
  for (const k of ["parent", "lib", "owner"]) if (!cfg[k]) throw new Error(`${k.toUpperCase()} is not set`);
  P.decodeP2mrAddress(cfg.owner, net.network);
  // fail loudly, every run, if the seed is missing or is not the key that holds the parent (a red run in the Actions tab)
  const w = await walletFromSeed(env.QBIT_SEED || "");
  const holder = (await qord(`/r/inscription/${cfg.parent}`)).address;
  if (holder !== w.address) throw new Error(`QBIT_SEED is the key of ${w.address.slice(0, 14)}…, but the parent is held by ${String(holder).slice(0, 14)}…`);
  const s = await survey(cfg);
  log(`tip ${s.tip}, viewer ${s.viewerHeight}, minted ${s.kids.length}/${cfg.cap}, payments ${s.payments.length}, waiting ${s.pending.length}`);
  if (s.viewerHeight < s.tip - 1) { log("the viewer is behind the chain; waiting for it (a batch in flight may not be indexed yet)"); return { busy: true }; }
  const parent = await locateParent(cfg.parent);
  if (!parent.confirmed) { log("the parent's last move is not confirmed yet; one batch at a time"); return { busy: true }; }
  if (parent.height > s.viewerHeight) { log("the viewer has not indexed the parent's last move yet"); return { busy: true }; }
  const room = cfg.cap - s.kids.length;
  let todo = s.pending.slice(0, Math.max(0, room)).slice(0, cfg.batch).map((p) => ({ ...p, pay: p.txid }));
  if (s.pending.length > room) log(`over the cap: ${s.pending.length - Math.max(0, room)} paid after the collection filled (refund them by hand): ${s.pending.slice(Math.max(0, room)).map((p) => p.txid.slice(0, 12)).join(" ")}`);
  if (free > 0 && room > 0) { // a rehearsal or the founder's own pieces: by hand only, never from the schedule
    const n = Math.min(free, room, cfg.batch); todo = Array.from({ length: n }, (_, k) => ({ txid: "free", pay: `free-${s.kids.length + k + 1}`, to: env.FREE_TO || cfg.owner }));
    log(`free: ${n} flame(s) to ${(env.FREE_TO || cfg.owner).slice(0, 14)}… (not paid for; by hand only)`);
  }
  if (!todo.length && cfg.sweep && s.tip > cfg.end && room > 0) { // the sale is over: whatever is left goes to the owner so the whole set exists
    const n = Math.min(room, cfg.batch); todo = Array.from({ length: n }, (_, k) => ({ txid: "sweep", pay: `sweep-${s.kids.length + k + 1}`, to: cfg.owner }));
    log(`sweep: ${n} unsold flames to the owner`);
  }
  if (!todo.length) { log("nothing to inscribe"); return { done: true }; }
  const html = childHtml(cfg.parent, cfg.lib);
  const items = todo.map((t, k) => ({ type: "text/html;charset=utf-8", body: html, to: t.to, meta: { name: `BLACKBODY #${s.kids.length + k + 1}`, n: s.kids.length + k + 1, pay: t.pay } }));
  const label = todo.map((t) => t.pay).join(",");
  const exclude = [`${parent.txid}:${parent.vout}`];
  let coins = (await floatCoins(w.address, { exclude, need: 0n })).picked;
  const plan = await planBatch(w, { items, parent, rate: cfg.rate, label, coins });
  const f = await floatCoins(w.address, { exclude, need: plan.need });
  if (f.sum < plan.need) throw new Error(`the collection address ${w.address} needs ${qbt(plan.need)} QBT of plain coins, has ${qbt(f.sum)}`);
  coins = f.picked;
  const b = buildBatch(w, plan, { coins, parent, rate: cfg.rate });
  log(`batch of ${items.length}: #${s.kids.length + 1}..#${s.kids.length + items.length}; reveal fee ${qbt(plan.revealFee)} + commit fee ${qbt(b.commitFee)} QBT; reveal ${b.reveal.length} B`);
  items.forEach((it, k) => log(`  #${s.kids.length + k + 1} -> ${it.to.slice(0, 14)}…  for ${todo[k].txid === "sweep" ? "sweep" : todo[k].txid.slice(0, 12)}`));
  if (!send) { log("dry run, nothing sent. Add --send."); return { dry: true, count: items.length }; }
  // the commit may already be on the chain from a run that died before the reveal (same batch, same one-time key)
  let commitKnown = false;
  try { await api(`/tx/${b.commitId}/status`); commitKnown = true; } catch { /* not known */ }
  if (!commitKnown) { const id = await pushWithRetry(hex(b.commit)); log("commit", id); if (id !== b.commitId) throw new Error(`node txid ${id} differs from ${b.commitId}`); }
  else log("commit already known:", b.commitId);
  const rid = await pushWithRetry(hex(b.reveal), 12); log("reveal", rid);
  return { sent: true, reveal: rid, count: items.length };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const cmd = process.argv[2] || "status";
  try {
    if (cmd === "run") { const fi = process.argv.indexOf("--free"); const r = await run({ send: process.argv.includes("--send"), free: fi > 0 ? +process.argv[fi + 1] : 0 }); process.exitCode = 0; if (r.busy) log("busy, will retry on the next run"); }
    else if (cmd === "status") {
      const cfg = cfgFromEnv(); const s = await survey(cfg);
      log(`tip ${s.tip}; minted ${s.kids.length}/${cfg.cap}; payments ${s.payments.length}; waiting ${s.pending.length}`);
      s.pending.forEach((p) => log(`  waiting ${p.txid.slice(0, 16)}… from ${p.to.slice(0, 14)}… ${qbt(p.paid)} QBT at block ${p.height}`));
    } else throw new Error("usage: clerk.mjs run [--send] | status");
  } catch (e) { console.error("clerk:", e.message); process.exitCode = 1; }
}
