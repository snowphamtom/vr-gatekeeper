/**
 * Headroom Admission Engine — JavaScript port of
 * /home/hatch/workspace/refuse/engine/headroom_engine.py
 *
 * Canonical: S_H = S_solv * R_H
 * GRANT iff ProspectiveClaimed <= Supported AND |r_H| <= epsilon_H
 * TripleEcho is observer-only (Phi_H cannot buy R_H / Case D).
 *
 * Plain ES module, zero dependencies. Runs in browsers and Node.
 *
 * Fidelity notes vs the Python original:
 * - Same DIMS, same EPS_H_DEFAULT = 1e-6, same reason strings, same gate math.
 * - HashLedger chains identically (prev + "|" + canonical body), but digests are
 *   NOT byte-identical to Python's: Python's json float repr and JS number
 *   formatting differ on edge cases. Chain mechanics (genesis, prev-linking,
 *   append-only) match exactly.
 * - illustrativeQueryInput() is a DEMO helper mirroring mcp_server.py's
 *   "illustrative mapping" (token-affinity + hash-derived pairs). It is NOT
 *   part of the gate math. Benign demo queries -> coherent pairs (r_H ~ 0);
 *   injection-pattern queries -> divergent pairs (r_H >> epsilon).
 */

export const DIMS = ["compute", "memory", "power", "thermal"];
export const EPS_H_DEFAULT = 1e-6;
export const PPA_REF = "Headroom PPA 64/150,688"; // design nucleus; not Magpie DEN

/* ------------------------------------------------------------------ */
/* Synchronous SHA-256 (bundled; no Node crypto / no SubtleCrypto).    */
/* ------------------------------------------------------------------ */
const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function _rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

export function sha256Hex(str) {
  // UTF-8 encode
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) bytes.push(c);
    else if (c < 0x800) bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      const hi = c, lo = str.charCodeAt(++i);
      const cp = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
      bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  const bitLen = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  // 64-bit length, big-endian (high word first; assumes < 2^32 bits... use full 64-bit)
  const hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
  bytes.push((hi >>> 24) & 0xff, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff,
             (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Array(64);

  for (let off = 0; off < bytes.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = (bytes[off + i * 4] << 24) | (bytes[off + i * 4 + 1] << 16) |
             (bytes[off + i * 4 + 2] << 8) | bytes[off + i * 4 + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + w[i]) | 0;
      const S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((x) => (x >>> 0).toString(16).padStart(8, "0"))
    .join("");
}

/* Canonical JSON with sorted keys (matches Python json.dumps sort_keys=True). */
function canonicalStringify(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v === "number") {
    if (!isFinite(v)) return "null";
    return JSON.stringify(v);
  }
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalStringify).join(", ") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ": " + canonicalStringify(v[k])).join(", ") + "}";
}

/* ------------------------------------------------------------------ */
/* ResourceVector — four-rail resource word.                            */
/* ------------------------------------------------------------------ */
export class ResourceVector {
  constructor(compute = 0, memory = 0, power = 0, thermal = 0) {
    this.compute = compute;
    this.memory = memory;
    this.power = power;
    this.thermal = thermal;
  }
  asTuple() {
    return [this.compute, this.memory, this.power, this.thermal];
  }
  add(other) {
    const a = this.asTuple(), b = other.asTuple();
    return new ResourceVector(a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]);
  }
  sub(other) {
    const a = this.asTuple(), b = other.asTuple();
    return new ResourceVector(a[0] - b[0], a[1] - b[1], a[2] - b[2], a[3] - b[3]);
  }
  mul(scalar) {
    const a = this.asTuple();
    return new ResourceVector(a[0] * scalar, a[1] * scalar, a[2] * scalar, a[3] * scalar);
  }
  componentwiseLe(other) {
    const a = this.asTuple(), b = other.asTuple();
    return a.every((x, i) => x <= b[i] + 1e-15);
  }
  clampNonneg() {
    const a = this.asTuple();
    return new ResourceVector(Math.max(0, a[0]), Math.max(0, a[1]), Math.max(0, a[2]), Math.max(0, a[3]));
  }
  maxNorm() {
    return Math.max(...this.asTuple().map(Math.abs));
  }
  toDict() {
    return { compute: this.compute, memory: this.memory, power: this.power, thermal: this.thermal };
  }
  static fromSeq(seq) {
    const vals = [...seq, 0, 0, 0, 0].slice(0, 4).map(Number);
    return new ResourceVector(vals[0], vals[1], vals[2], vals[3]);
  }
  static ones(scale = 1.0) {
    return new ResourceVector(scale, scale, scale, scale);
  }
}

/* ------------------------------------------------------------------ */
/* HowardResidual — H_ij = d_ij - lambda * D_K(i,j); RMS aggregate.     */
/* ------------------------------------------------------------------ */
export class HowardResidual {
  constructor(r_H = 0.0, lambdaScale = 1.0, pairs = []) {
    this.r_H = r_H;
    this.lambdaScale = lambdaScale;
    this.pairs = pairs; // [[d, D_K], ...]
  }
  recompute() {
    if (!this.pairs.length) {
      this.r_H = 0.0;
      return this.r_H;
    }
    let num = 0.0, den = 0.0;
    for (const [d, dk] of this.pairs) {
      num += d * dk;
      den += dk * dk;
    }
    if (den > 0) {
      this.lambdaScale = Math.max(0.0, num / (den + 1e-18));
    }
    const residuals = this.pairs.map(([d, dk]) => d - this.lambdaScale * dk);
    this.r_H = Math.sqrt(residuals.reduce((s, r) => s + r * r, 0) / residuals.length);
    return this.r_H;
  }
  valid(epsilon_H = EPS_H_DEFAULT) {
    return Math.abs(this.r_H) <= epsilon_H;
  }
}

/* Minimal complex helpers for the observer. */
function _cabs(z) { return Math.hypot(z.re, z.im); }
function _cconj(z) { return { re: z.re, im: -z.im }; }
function _cmul(a, b) {
  return { re: a.re * b.re - a.im * b.im, im: a.re * b.im + a.im * b.re };
}

/* ------------------------------------------------------------------ */
/* TripleEchoObserver — observer-only coherence. NEVER admission auth.  */
/* ------------------------------------------------------------------ */
export class TripleEchoObserver {
  constructor() {
    this.lanes = [{ re: 0, im: 0 }, { re: 0, im: 0 }, { re: 0, im: 0 }];
    this.phi_H = 0.0;
  }
  observe(z1, z2, z3) {
    this.lanes = [z1, z2, z3];
    const mags = this.lanes.map(_cabs);
    if (Math.min(...mags) < 1e-18) {
      this.phi_H = 0.0;
      return this.phi_H;
    }
    const u = this.lanes.map((z) => {
      const m = _cabs(z);
      return { re: z.re / m, im: z.im / m };
    });
    const c12 = _cabs(_cmul(_cconj(u[0]), u[1]));
    const c23 = _cabs(_cmul(_cconj(u[1]), u[2]));
    const c31 = _cabs(_cmul(_cconj(u[2]), u[0]));
    const bal = 1.0 - (Math.max(...mags) - Math.min(...mags)) / (mags.reduce((s, m) => s + m, 0) + 1e-18);
    this.phi_H = Math.max(0.0, Math.min(1.0, ((c12 + c23 + c31) / 3.0) * bal));
    return this.phi_H;
  }
  note() {
    return `Phi_H=${this.phi_H.toFixed(4)} (observer-only; not admission authority)`;
  }
}

/* ------------------------------------------------------------------ */
/* HashLedger — append-only sha256-chained decision log (in-memory).    */
/* ------------------------------------------------------------------ */
export class HashLedger {
  constructor(genesis = "HEADROOM_SEAL_v1") {
    this.chain = [];
    this._prev = sha256Hex(genesis);
  }
  append(record) {
    const body = canonicalStringify(record);
    const digest = sha256Hex(this._prev + "|" + body);
    const entry = {
      n: this.chain.length,
      prev: this._prev.slice(0, 16),
      digest,
      record,
      ts: Date.now() / 1000,
    };
    this.chain.push(entry);
    this._prev = digest;
    return digest;
  }
  tip() {
    return this._prev;
  }
  ribbon(n = 12) {
    return this.chain.slice(-n).map((e) => e.digest.slice(0, 12));
  }
  toList() {
    return [...this.chain];
  }
}

/* ------------------------------------------------------------------ */
/* HeadroomAdmissionController — S_H = S_solv * R_H.                     */
/* ------------------------------------------------------------------ */
export class HeadroomAdmissionController {
  constructor({ supported = null, epsilon_H = EPS_H_DEFAULT, ledger = null } = {}) {
    this.supported = supported || new ResourceVector(100.0, 100.0, 100.0, 100.0);
    this.active = new ResourceVector();
    this.epsilon_H = epsilon_H;
    this.ledger = ledger || new HashLedger();
    this.echo = new TripleEchoObserver();
    this.howard = new HowardResidual();
    this.telemetryTicks = 0;
    this.admits = 0;
    this.refuses = 0;
    this.ppaRef = PPA_REF;
  }

  get interior() {
    return this.supported.sub(this.active).clampNonneg();
  }

  updateTelemetry({ supported = null, release = null, scale = null } = {}) {
    this.telemetryTicks += 1;
    if (supported !== null) this.supported = supported;
    if (release !== null) this.active = this.active.sub(release).clampNonneg();
    if (scale !== null) {
      const s = Math.max(0.0, Math.min(1.0, scale));
      this.supported = new ResourceVector(
        this.supported.compute,
        this.supported.memory,
        this.supported.power * s,
        this.supported.thermal * s
      );
    }
    return this.interior;
  }

  evaluate(R, { pairs = null, echo = null, meta = null } = {}) {
    if (pairs !== null) {
      this.howard.pairs = pairs.map((p) => [p[0], p[1]]);
      this.howard.recompute();
    }
    let phi = 0.0;
    if (echo !== null) {
      phi = this.echo.observe(echo[0], echo[1], echo[2]);
    } else {
      phi = this.echo.phi_H;
    }

    const interior = this.interior;
    const S_solv = R.componentwiseLe(interior) ? 1 : 0;
    const R_H = this.howard.valid(this.epsilon_H) ? 1 : 0;
    const S_H = S_solv * R_H; // product = AND; Phi cannot buy R_H

    let admit, reason;
    if (S_H === 1) {
      // Atomic commit of whole resource-state transition
      this.active = this.active.add(R);
      this.admits += 1;
      reason = "CRYSTALLIZE";
      admit = true;
    } else {
      // Refusal purity: ActiveClaimed unchanged
      this.refuses += 1;
      admit = false;
      if (S_solv === 0 && R_H === 0) reason = "DISSOLVE:insolvence+residual";
      else if (S_solv === 0) reason = "DISSOLVE:insolvence";
      else reason = "DISSOLVE:residual";
    }

    const verdict = {
      admit,
      S_solv,
      R_H,
      S_H,
      reason,
      r_H: this.howard.r_H,
      phi_H: phi,
      claimed: R.toDict(),
      interior: interior.toDict(),
      digest: "",
    };
    const digest = this.ledger.append({
      S_H,
      S_solv,
      R_H,
      r_H: this.howard.r_H,
      phi_H: phi,
      admit,
      reason,
      meta: meta || {},
      ppa: this.ppaRef,
    });
    verdict.digest = digest;
    return verdict;
  }
}

/* ------------------------------------------------------------------ */
/* DEMO ONLY — illustrative text -> engine mapping.                     */
/* Mirrors mcp_server.py's "illustrative mapping" (token affinity +     */
/* hash-derived pairs). NOT part of the gate math. The gate itself      */
/* only ever sees (ResourceVector, pairs).                              */
/* ------------------------------------------------------------------ */

// FNV-1a 32-bit, deterministic across runs.
export function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

// Injection-pattern tokens. A query containing any of these is mapped to
// DIVERGENT Howard pairs (r_H >> epsilon -> REFUSE). Everything else maps
// to COHERENT pairs (r_H == 0 -> eligible to ADMIT, solvency permitting).
export const INJECTION_TOKENS = [
  "ignore", "reveal", "system prompt", "bypass", "roleplay",
  "jailbreak", "disregard", "override", "forget your", "pretend",
];

export function isInjectionPattern(query) {
  const q = query.toLowerCase();
  return INJECTION_TOKENS.some((t) => q.includes(t));
}

/**
 * Deterministic illustrative mapping: query text -> { R, pairs }.
 * - R from query shape (mirrors mcp_server.py): word-count scaled.
 * - Benign: coherent pairs [[d1,d1],[d2,d2]] -> r_H exactly 0.
 * - Injection pattern: divergent pairs from hash -> r_H >> 1e-6.
 */
export function illustrativeQueryInput(query) {
  const w = query.split(/\s+/).filter(Boolean).length;
  const R = new ResourceVector(Math.min(8.0, 1.0 + w / 12.0), 2.0, 1.0, 0.8);
  const h = fnv1a(query);
  let pairs;
  if (isInjectionPattern(query)) {
    const x = (h % 1000) / 1000;
    let y = ((h >>> 13) % 1000) / 1000;
    if (Math.abs(x - y) < 0.05) y = 1 - y; // guarantee divergence
    const a = 0.1 + 0.8 * x, b = 0.1 + 0.8 * y;
    pairs = [[a, b], [b, a]];
  } else {
    const d1 = 0.3 + 0.5 * ((h % 1000) / 1000);
    const d2 = 0.3 + 0.5 * (((h >>> 16) % 1000) / 1000);
    pairs = [[d1, d1], [d2, d2]];
  }
  return { R, pairs, injection: isInjectionPattern(query) };
}

/** Convenience: run a full demo evaluation on a FRESH controller. */
export function demoEvaluate(query) {
  const ctl = new HeadroomAdmissionController();
  const { R, pairs } = illustrativeQueryInput(query);
  return ctl.evaluate(R, { pairs, meta: { t: query.slice(0, 80) } });
}
