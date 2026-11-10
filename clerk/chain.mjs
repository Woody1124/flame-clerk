// Qbit transactions for BLACKBODY: plain inscriptions (the library, the parent) and batches of children
// whose reveal spends the parent first (exactly the layout ord, and so qord, expects).
//   input 0  the parent's coin (the collection key signs a plain leaf)
//   input 1  the commit output (a one-time key signs the leaf that carries the envelopes)
//   output 0 the parent, back to the collection address; outputs 1..N one child each
import { createHash, createHmac } from "node:crypto";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { HDKey } from "@scure/bip32";
import * as pqc from "@qbit-oss/pqc";
import * as P from "@qbit-oss/protocol";

export { P, pqc };
export const POSTAGE = 10_000n; // qord's postage: every inscription output holds exactly this
const V = P.P2MR_LEAF_VERSION_V1;
const UA = { "User-Agent": "Mozilla/5.0 blackbody-clerk" };
export const net = {
  api: process.env.QBIT_API || "https://mempool.qbit.org/api",
  qord: process.env.QORD_URL || "https://qord.hepworth.app",
  network: process.env.QBIT_NETWORK || "mainnet",
};

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
export const qbt = (bits) => (Number(bits) / 1e8).toFixed(8).replace(/\.?0+$/, "") || "0";

async function fetchJson(url, init) {
  const r = await fetch(url, { headers: { ...UA, accept: "application/json" }, ...init });
  const t = await r.text();
  if (!r.ok) throw Object.assign(new Error(`${url}: HTTP ${r.status} ${t.slice(0, 120)}`), { status: r.status });
  try { return JSON.parse(t); } catch { return t; }
}
export const api = (p) => fetchJson(net.api + p);
export const qord = (p) => fetchJson(net.qord + p);
export async function broadcast(hex) {
  const r = await fetch(`${net.api}/tx/push`, { method: "POST", headers: { ...UA, "content-type": "text/plain" }, body: `txHash=${hex}` });
  const t = (await r.text()).trim();
  if (!r.ok || !/^[0-9a-f]{64}$/.test(t)) throw new Error(`broadcast: ${t.slice(0, 300)}`);
  return t;
}

// ---------- keys
export async function walletFromSeed(words) {
  words = words.trim().toLowerCase().split(/\s+/).join(" ");
  if (!validateMnemonic(words, wordlist)) throw new Error("the seed phrase is not a valid BIP39 mnemonic");
  await pqc.init();
  const leaf = HDKey.fromMasterSeed(mnemonicToSeedSync(words)).derive("m/87'/0'/0'/0").deriveChild(0).privateKey;
  const key = pqc.derivePQCKey(leaf, 0, 0, 0);
  const address = P.p2mrAddressFromPubkey(key.pk32, net.network);
  const leafScript = P.singleKeyLeafScript(key.pk32);
  return { key, leafPriv: leaf, address, script: P.addressToScriptPubKey(address, net.network), leafScript, leafHash: P.p2mrLeafHash(V, leafScript), control: P.buildControlBlock(V) };
}
// A one-time reveal key derived from the collection key and the batch it serves: the same batch always gives the same
// key, so a run that died between commit and reveal can pick the commit output up again, and nothing needs saving.
export function oneTimeKey(w, label) {
  const mac = (n) => createHmac("sha256", Buffer.from(w.leafPriv)).update(`BB1-reveal|${label}|${n}`).digest();
  return pqc.keygen(Uint8Array.from(Buffer.concat([mac(0), mac(1), mac(2), mac(3)]))); // 128 bytes of entropy
}

// ---------- bytes
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const vi = (n) => (n < 0xfd ? Buffer.from([n]) : n <= 0xffff ? Buffer.from([0xfd, n & 255, n >> 8]) : Buffer.from([0xfe, ...u32(n)]));
const item = (d) => Buffer.concat([vi(d.length), Buffer.from(d)]);
export const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
export const hex = (u) => Buffer.from(u).toString("hex");
const sha256d = (b) => createHash("sha256").update(createHash("sha256").update(b).digest()).digest();

export function serializeTx({ inputs, outputs, version = 2, locktime = 0 }) {
  const parts = [u32(version), Buffer.from([0, 1]), vi(inputs.length)];
  for (const i of inputs) parts.push(Buffer.from(unhex(i.txid).reverse()), u32(i.vout), vi(0), u32(i.sequence ?? 0xfffffffd));
  parts.push(vi(outputs.length));
  for (const o of outputs) parts.push(u64(o.value), vi(o.script.length), Buffer.from(o.script));
  for (const i of inputs) { parts.push(vi(i.witness.length)); for (const w of i.witness) parts.push(item(w)); }
  parts.push(u32(locktime));
  return Uint8Array.from(Buffer.concat(parts));
}
export function parseTx(raw) {
  const b = Buffer.from(raw); let i = 0;
  const rv = () => { const f = b[i++]; if (f < 0xfd) return f; if (f === 0xfd) { const v = b.readUInt16LE(i); i += 2; return v; } const v = b.readUInt32LE(i); i += 4; return v; };
  const version = b.readUInt32LE(i); i += 4;
  let segwit = false; if (b[i] === 0 && b[i + 1] === 1) { segwit = true; i += 2; }
  const start = i, nin = rv(), inputs = [];
  for (let k = 0; k < nin; k++) { const txid = Buffer.from(b.subarray(i, i + 32)).reverse().toString("hex"); i += 32; const vout = b.readUInt32LE(i); i += 4; const sl = rv(); i += sl; const sequence = b.readUInt32LE(i); i += 4; inputs.push({ txid, vout, sequence, witness: [] }); }
  const nout = rv(), outputs = [];
  for (let k = 0; k < nout; k++) { const value = b.readBigUInt64LE(i); i += 8; const sl = rv(); outputs.push({ value, script: Uint8Array.from(b.subarray(i, i + sl)) }); i += sl; }
  const endOuts = i;
  if (segwit) for (const inp of inputs) { const n = rv(); for (let k = 0; k < n; k++) { const l = rv(); inp.witness.push(Uint8Array.from(b.subarray(i, i + l))); i += l; } }
  const locktime = b.readUInt32LE(i);
  const stripped = Buffer.concat([b.subarray(0, 4), b.subarray(start, endOuts), b.subarray(b.length - 4)]);
  return { version, inputs, outputs, locktime, txid: Buffer.from(sha256d(stripped)).reverse().toString("hex"), size: b.length };
}
export const txidOf = (raw) => parseTx(raw).txid;
export const vsize = (raw) => Math.ceil(raw.length / 4); // the explorer's vB
export const feeFor = (rate, raw) => BigInt(Math.ceil(rate * vsize(raw)));

// ---------- envelope (byte for byte as qord writes it)
const push = (b) => { const n = b.length; if (n === 0) return [0x00]; if (n <= 75) return [n, ...b]; if (n <= 255) return [0x4c, n, ...b]; return [0x4d, n & 255, n >> 8, ...b]; };
const tagged = (tag, value) => [...push([tag]), ...push(value)];
const utf8 = (s) => new TextEncoder().encode(s);
export function cbor(v) { // small subset: unsigned ints, text, maps with text keys
  const head = (major, n) => (n < 24 ? [(major << 5) | n] : n < 256 ? [(major << 5) | 24, n] : n < 65536 ? [(major << 5) | 25, n >> 8, n & 255] : [(major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255]);
  if (typeof v === "number") return head(0, v);
  if (typeof v === "string") { const b = utf8(v); return [...head(3, b.length), ...b]; }
  const keys = Object.keys(v); return [...head(5, keys.length), ...keys.flatMap((k) => [...cbor(k), ...cbor(v[k])])];
}
export function cborDecode(bytes) { // the same subset
  const b = Buffer.from(bytes); let i = 0;
  const arg = (ai) => { if (ai < 24) return ai; if (ai === 24) return b[i++]; if (ai === 25) { const v = b.readUInt16BE(i); i += 2; return v; } const v = b.readUInt32BE(i); i += 4; return v; };
  const rd = () => { const t = b[i++], major = t >> 5, n = arg(t & 31); if (major === 0) return n; if (major === 3) { const s = b.subarray(i, i + n).toString("utf8"); i += n; return s; } if (major === 5) { const o = {}; for (let k = 0; k < n; k++) { const key = rd(); o[key] = rd(); } return o; } throw new Error("cbor: unsupported type " + major); };
  return rd();
}
// ord writes an inscription id as the txid in internal byte order, then the index as little-endian without trailing zeros
export function idToBytes(id) {
  const m = /^([0-9a-f]{64})i(\d+)$/.exec(id); if (!m) throw new Error("bad inscription id " + id);
  const out = [...unhex(m[1]).reverse()]; let n = +m[2]; while (n > 0) { out.push(n & 255); n >>= 8; }
  return Uint8Array.from(out);
}
const leBytes = (n) => { const o = []; while (n > 0) { o.push(n & 255); n = Math.floor(n / 256); } return Uint8Array.from(o); };
export function envelope({ type, body, parent, pointer, meta }) {
  const out = [0x00, 0x63, ...push(utf8("ord"))]; // OP_FALSE OP_IF "ord"
  out.push(...tagged(1, utf8(type)));
  if (parent) out.push(...tagged(3, idToBytes(parent)));
  if (pointer) out.push(...tagged(2, leBytes(pointer)));
  if (meta) { const md = Uint8Array.from(cbor(meta)); for (let i = 0; i < md.length; i += 520) out.push(...tagged(5, md.slice(i, i + 520))); }
  out.push(...push([])); // body marker
  const bb = typeof body === "string" ? utf8(body) : body;
  for (let i = 0; i < bb.length; i += 520) out.push(...push(bb.slice(i, i + 520)));
  out.push(0x68); // OP_ENDIF
  return Uint8Array.from(out);
}
// Reads every envelope in a leaf script (the way an indexer does): [{type, parent, pointer, meta, body}]
export function parseEnvelopes(leaf) {
  const s = Buffer.from(leaf); let i = 34;
  const rd = () => { const op = s[i++]; if (op === 0x00) return { op, d: Buffer.alloc(0) }; if (op <= 75) { const d = s.subarray(i, i + op); i += op; return { op, d }; } if (op === 0x4c) { const n = s[i++]; const d = s.subarray(i, i + n); i += n; return { op, d }; } if (op === 0x4d) { const n = s.readUInt16LE(i); i += 2; const d = s.subarray(i, i + n); i += n; return { op, d }; } return { op, d: null }; };
  const out = [];
  while (i < s.length) {
    if (s[i] !== 0x00 || s[i + 1] !== 0x63) break; i += 2;
    if (rd().d.toString() !== "ord") break;
    const e = { type: "", parent: null, pointer: null, meta: null, body: Buffer.alloc(0) }, metaParts = [], bodyParts = [];
    for (;;) {
      const a = rd();
      if (a.op === 0x68) break;
      if (a.op === 0x00) { while (s[i] !== 0x68) bodyParts.push(rd().d); i++; break; }
      const v = rd(), t = a.d[0];
      if (t === 1) e.type = v.d.toString(); else if (t === 3) e.parent = Buffer.from(v.d); else if (t === 2) e.pointer = v.d.readUIntLE(0, v.d.length || 1); else if (t === 5) metaParts.push(v.d);
    }
    e.body = Buffer.concat(bodyParts); if (metaParts.length) e.meta = Buffer.concat(metaParts);
    out.push(e);
  }
  return out;
}

// ---------- spending the collection key's plain coins
export async function carriesSomething(outpoint) { // an inscription, a rune, or unknown to the viewer: never spend it
  try {
    const j = await qord(`/output/${outpoint}`);
    return (j.inscriptions?.length ?? 0) > 0 || Object.keys(j.runes ?? {}).length > 0 || j.indexed === false || j.spent === true;
  } catch { return true; }
}
export async function floatCoins(address, { exclude = [], need = 0n, max = 6 } = {}) {
  const all = (await api(`/address/${address}/utxo`)).filter((u) => u.status?.confirmed && BigInt(u.value) > POSTAGE && !exclude.includes(`${u.txid}:${u.vout}`)).sort((a, b) => b.value - a.value);
  const picked = []; let sum = 0n;
  for (const u of all) {
    if (picked.length >= max) break;
    if (await carriesSomething(`${u.txid}:${u.vout}`)) continue;
    picked.push(u); sum += BigInt(u.value);
    if (sum >= need) break;
  }
  return { picked, sum };
}
function commitTx(w, coins, commitScript, commitValue, fee) {
  const total = coins.reduce((s, u) => s + BigInt(u.value), 0n);
  const change = total - commitValue - fee;
  const outputs = [{ value: commitValue, scriptPubKey: commitScript }];
  if (change >= POSTAGE) outputs.push({ value: change, scriptPubKey: w.script });
  const psbt = P.createP2mrPsbt({
    version: 2, locktime: 0,
    inputs: coins.map((u) => ({ prevout: { txid: unhex(u.txid).reverse(), vout: u.vout }, witnessUtxo: { value: BigInt(u.value), scriptPubKey: w.script }, controlBlock: w.control, leafScript: w.leafScript, leafVersion: V, merkleRoot: w.leafHash, sequence: 0xfffffffd })),
    outputs,
  });
  const signed = P.signP2mrPsbt({ psbt, keys: coins.map((_, inputIndex) => ({ inputIndex, pubkey: w.key.pk32, leafHash: w.leafHash })), sign: (h) => pqc.sign(w.key.sk64, h) });
  const raw = P.extractP2mrTransaction(P.finalizeP2mrPsbt(signed.psbt));
  return { raw, change: change >= POSTAGE ? change : 0n };
}
// Reveal: [parent coin (collection key)?, commit output (one-time key)]. Signed by hand: the helper only knows plain leaves.
function revealTx(w, ek, revealLeaf, commit, parent, outs) {
  const eHash = P.p2mrLeafHash(V, revealLeaf), commitScript = P.p2mrScriptPubKey(eHash);
  const inputs = [], spent = [];
  if (parent) { inputs.push({ txid: parent.txid, vout: parent.vout, sequence: 0xfffffffd }); spent.push({ value: BigInt(parent.value), scriptPubKey: w.script }); }
  inputs.push({ txid: commit.txid, vout: commit.vout, sequence: 0xfffffffd }); spent.push({ value: BigInt(commit.value), scriptPubKey: commitScript });
  const sighash = (idx, leafHash) => P.p2mrSighash({
    tx: { version: 2, locktime: 0, inputs: inputs.map((x) => ({ prevout: { txid: unhex(x.txid).reverse(), vout: x.vout }, sequence: x.sequence })), outputs: outs.map((o) => ({ value: o.value, scriptPubKey: o.script })) },
    inputIndex: idx, spentOutputs: spent, leafHash,
  });
  const witnesses = [];
  if (parent) witnesses.push([pqc.sign(w.key.sk64, sighash(0, w.leafHash)), w.leafScript, w.control]);
  witnesses.push([pqc.sign(ek.secretKey, sighash(inputs.length - 1, eHash)), revealLeaf, w.control]);
  return serializeTx({ inputs: inputs.map((x, k) => ({ ...x, witness: witnesses[k] })), outputs: outs.map((o) => ({ value: o.value, script: o.script })) });
}

// Plan (and optionally return the raw transactions of) one commit+reveal that inscribes `items` in one batch.
//   items: [{ type, body, meta?, to }]   parent: { id, txid, vout, value } or null
//   Builds with placeholders first to learn the sizes, then for real.
export async function planBatch(w, { items, parent, rate, label, coins }) {
  const ek = oneTimeKey(w, label);
  const pv = parent ? BigInt(parent.value) : 0n;
  const envs = items.map((it, k) => envelope({ type: it.type, body: it.body, meta: it.meta, parent: parent ? parent.id : undefined, pointer: parent ? Number((BigInt(k) + 1n) * POSTAGE) : undefined }));
  const revealLeaf = Uint8Array.from([...P.singleKeyLeafScript(ek.publicKey), ...envs.flatMap((e) => [...e])]);
  const commitScript = P.p2mrScriptPubKey(P.p2mrLeafHash(V, revealLeaf));
  const outs = [];
  if (parent) outs.push({ value: pv, script: w.script });
  items.forEach((it) => outs.push({ value: POSTAGE, script: P.addressToScriptPubKey(it.to, net.network) }));
  const probeReveal = revealTx(w, ek, revealLeaf, { txid: "00".repeat(32), vout: 0, value: 100_000_000 }, parent && { ...parent, txid: "11".repeat(32) }, outs);
  const revealFee = feeFor(rate, probeReveal);
  const commitValue = revealFee + BigInt(items.length) * POSTAGE;
  const need = commitValue + feeFor(rate, new Uint8Array(4200 + 3700 * Math.max(0, (coins?.length ?? 1) - 1))) + 20_000n;
  return { ek, revealLeaf, commitScript, outs, revealFee, commitValue, need, envs, pv };
}
export function buildBatch(w, plan, { coins, parent, rate }) {
  const { ek, revealLeaf, commitScript, outs, commitValue } = plan;
  let fee = feeFor(rate, commitTx(w, coins, commitScript, commitValue, 1_000_000n).raw);
  let commit = commitTx(w, coins, commitScript, commitValue, fee);
  const commitId = txidOf(commit.raw);
  const reveal = revealTx(w, ek, revealLeaf, { txid: commitId, vout: 0, value: commitValue }, parent, outs);
  return { commit: commit.raw, commitId, commitFee: fee, reveal, revealId: txidOf(reveal), change: commit.change };
}

// ---------- waiting
export async function confirmed(txid) { try { return (await api(`/tx/${txid}/status`)).confirmed === true; } catch { return false; } }
export async function pushWithRetry(hex, tries = 10) {
  let last;
  for (let t = 0; t < tries; t++) { try { return await broadcast(hex); } catch (e) { last = e; await sleep(3000); } }
  throw last;
}
