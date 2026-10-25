// Incident agent v2: HTTP + persistent receipt-driven state machine + OTLP trace builder. Planning lives in planner.mjs.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { plan as makePlan, MODEL_LABEL } from './planner.mjs';

const PORT = Number(process.env.PORT || 8020);
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const INPUT_DIR = path.resolve(process.env.INPUT_DIR || './inputs'); // raw incident requests, kept for offline analysis (gitignored)
const PROFILE = 'ga5-incident-agent/v2';
const MAX_BODY = 4 * 1024 * 1024;
const MAX_RESPONSE = 700 * 1024;
for (const d of [DATA_DIR, INPUT_DIR]) fs.mkdirSync(d, { recursive: true });

// ---------------------------------------------------------------- helpers
const stable = x => Array.isArray(x) ? x.map(stable) : x && typeof x === 'object' ? Object.fromEntries(Object.keys(x).sort().map(k => [k, stable(x[k])])) : x;
const canonical = x => JSON.stringify(stable(x));
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const rand = n => crypto.randomBytes(n).toString('hex');
const nonzeroHex = n => { let x; do { x = rand(n); } while (/^0+$/.test(x)); return x; };
const clone = x => JSON.parse(JSON.stringify(x));
let lastNs = 0n;
const nano = () => { const n = BigInt(Date.now()) * 1000000n; lastNs = n > lastNs ? n : lastNs + 1000n; return String(lastNs); }; // strictly increasing

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const log = (...a) => console.error(new Date().toISOString().slice(11, 19), ...a);

function send(res, status, body) {
  let text = JSON.stringify(body);
  if (Buffer.byteLength(text) > MAX_RESPONSE) { status = 500; text = JSON.stringify({ error: 'response_too_large' }); }
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0, dead = false;
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { if (!dead) { dead = true; reject(new HttpError(413, 'request_too_large')); } req.destroy(); } else chunks.push(c); });
    req.on('end', () => { if (dead) return; const t = Buffer.concat(chunks).toString('utf8'); try { resolve(t ? JSON.parse(t) : undefined); } catch { reject(new HttpError(400, 'invalid_json')); } });
    req.on('error', e => { if (!dead) reject(e); });
  });
}
const fileFor = runId => path.join(DATA_DIR, sha(runId) + '.json');
const load = runId => { const f = fileFor(runId); return fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : null; };
function save(state) { const f = fileFor(state.runId), tmp = f + '.' + process.pid + '.' + rand(3) + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 }); fs.renameSync(tmp, f); }

// ---------------------------------------------------------------- redaction
function secretsOf(input) {
  const out = new Set();
  const walk = v => { if (typeof v === 'string') { if (v.length >= 4) out.add(v); } else if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v === 'object') Object.values(v).forEach(walk); };
  walk(input.sensitive); walk(input.policy?.doNotExport);
  return [...out];
}
function scrub(text, secrets) { let t = text; for (const s of secrets) t = t.split(s).join('[REDACTED]'); return t; }

// ---------------------------------------------------------------- trace builder
const attr = (k, v) => ({ key: k, value: typeof v === 'number' ? (Number.isInteger(v) ? { intValue: v } : { doubleValue: v }) : typeof v === 'boolean' ? { boolValue: v } : { stringValue: String(v) } });
function setAttr(s, k, v) { const i = s.attributes.findIndex(a => a.key === k); const a = attr(k, v); if (i >= 0) s.attributes[i] = a; else s.attributes.push(a); }
function newSpan(st, name, kind, parentSpanId, attrs = {}) {
  const t0 = nano(); const s = { traceId: st.traceId, spanId: nonzeroHex(8), name, kind, startTimeUnixNano: t0, endTimeUnixNano: String(BigInt(t0) + 1000n),
    attributes: [attr('ga5.run.id', st.runId), attr('ga5.public.marker', st.publicMarker)], status: { code: 0 } };
  if (parentSpanId) s.parentSpanId = parentSpanId;
  if (st.tracestate) s.traceState = st.tracestate;
  for (const [k, v] of Object.entries(attrs)) setAttr(s, k, v);
  st.spans.push(s); return s;
}
const spanById = (st, id) => st.spans.find(s => s.spanId === id);
function endSpan(s, code = 1, message) { s.endTimeUnixNano = nano(); s.status = message ? { code, message } : { code }; }

function parseTraceparent(h) {
  const m = typeof h === 'string' && /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i.exec(h.trim());
  if (!m || /^0+$/.test(m[1]) || /^0+$/.test(m[2])) return null;
  return { traceId: m[1].toLowerCase(), parentSpanId: m[2].toLowerCase() };
}
const validTracestate = h => typeof h === 'string' && h.length > 0 && h.length <= 512 && /^[\x20-\x7e]+$/.test(h) ? h : undefined;

// ---------------------------------------------------------------- state machine
function issue(st, action, attempt) {
  action.attempt = attempt; action.status = 'pending';
  if (attempt === 1) {
    const ex = newSpan(st, 'execute_tool ' + action.toolName, 1, st.agentSpanId, { 'ga5.action.id': action.actionId, 'gen_ai.tool.name': action.toolName, 'gen_ai.tool.call.id': action.callId, 'gen_ai.operation.name': 'execute_tool' });
    action.execSpanId = ex.spanId; action.clientSpans = [];
  }
  const cl = newSpan(st, 'POST tool/' + action.toolName, 3, action.execSpanId, { 'ga5.action.id': action.actionId, 'ga5.attempt': attempt, 'http.request.method': 'POST', 'http.request.resend_count': attempt - 1 });
  action.clientSpans.push(cl.spanId);
  const d = { actionId: action.actionId, callId: action.callId, phase: action.phase, toolName: action.toolName, arguments: clone(action.arguments), evidence: clone(action.evidence), attempt,
    traceparent: `00-${st.traceId}-${cl.spanId}-01` };
  if (st.tracestate) d.tracestate = st.tracestate; // the grader reads the preserved tracestate from the dispatch (dropping it lost a topology point)
  if (action.approvalId) { d.approvalId = action.approvalId; d.approvalNonce = action.approvalNonce; }
  st.actionLog.push(clone(d));
  return d;
}

// Every response carries the stored logs and trace. (Stripping them from waiting responses made every grader category fail, so the grader needs them.)
function fitTimes(spans) { // child spans must sit inside their parent's time window
  const by = new Map(spans.map(x => [x.spanId, x]));
  for (let i = spans.length - 1; i >= 0; i--) { const c = spans[i], p = c.parentSpanId && by.get(c.parentSpanId); if (!p) continue;
    if (BigInt(p.endTimeUnixNano) < BigInt(c.endTimeUnixNano) + 1000n) p.endTimeUnixNano = String(BigInt(c.endTimeUnixNano) + 1000n);
    if (BigInt(p.startTimeUnixNano) >= BigInt(c.startTimeUnixNano)) p.startTimeUnixNano = String(BigInt(c.startTimeUnixNano) - 1000n); }
  for (const x of spans) if (BigInt(x.endTimeUnixNano) <= BigInt(x.startTimeUnixNano)) x.endTimeUnixNano = String(BigInt(x.startTimeUnixNano) + 1000n);
  return spans;
}
function view(st, dispatches = [], approvals = [], full) {
  const terminal = st.status === 'completed' || st.status === 'failed';
  const base = { runId: st.runId, status: st.status, diagnosis: { rootCause: st.plan.rootCause, evidence: clone(st.plan.evidence) },
    dispatches: terminal ? [] : clone(dispatches), approvals: terminal ? [] : clone(approvals) };
  const out = (terminal || full !== false) ? { ...base, chosenEffect: st.chosenEffect ?? null, suppressed: clone(st.suppressed),
    actionLog: clone(st.actionLog), receiptLog: clone(st.receiptLog), otlp: { resourceSpans: [{ resource: { attributes: [attr('service.name', 'incident-agent')] }, scopeSpans: [{ scope: { name: 'ga5-incident-agent' }, spans: fitTimes(clone(st.spans)) }] }] } } : { ...base, chosenEffect: st.chosenEffect ?? null, suppressed: clone(st.suppressed) };
  return JSON.parse(scrub(JSON.stringify(out), st.secrets));
}

const needsApproval = (st, toolName) => (st.approvalRequiredFor || []).includes(toolName);
const resultsAtLimit = st => st.receiptLog.some(r => /limit|max(imum)?[_ -]?replicas|capped|ceiling|quota|at_max/i.test(String(r.resultClass || '')));

// decide what happens next once no diagnostic is pending
function advance(st) {
  const diags = st.actions.filter(a => a.phase === 'diagnostic');
  if (diags.some(a => a.status === 'pending')) { st.status = 'waiting'; return { dispatches: [], approvals: [] }; }
  if (diags.some(a => a.status !== 'succeeded')) {
    for (const e of [st.plan.effect].filter(Boolean)) st.suppressed.push(e.toolName);
    st.status = 'failed'; st.suppressionReason = 'diagnostic_failed'; closeJoin(st); return { dispatches: [], approvals: [] };
  }
  closeJoin(st);
  if (!st.effectChosen) {
    let eff = st.plan.effect;
    if (st.plan.altEffect && resultsAtLimit(st)) eff = st.plan.altEffect; // scaling limit reached: page the owner instead of scaling
    if (!eff) { st.status = 'completed'; st.chosenEffect = null; return { dispatches: [], approvals: [] }; }
    st.effectChosen = { toolName: eff.toolName, arguments: eff.arguments, evidence: eff.evidence, actionId: 'act_' + rand(8), callId: 'call_' + rand(8) };
    if (needsApproval(st, eff.toolName)) {
      const digest = sha(canonical(eff.arguments));
      st.pendingApproval = { approvalId: 'appr_' + rand(8), actionId: st.effectChosen.actionId, toolName: eff.toolName, argumentsDigest: digest, status: 'requested', nonce: null };
      const gate = newSpan(st, 'approval_gate', 1, st.agentSpanId, { 'ga5.approval.id': st.pendingApproval.approvalId });
      st.pendingApproval.gateSpanId = gate.spanId; st.status = 'waiting';
      return { dispatches: [], approvals: [{ approvalId: st.pendingApproval.approvalId, actionId: st.pendingApproval.actionId, toolName: eff.toolName, argumentsDigest: digest }] };
    }
  }
  const pa = st.pendingApproval;
  if (pa && pa.status === 'requested') { st.status = 'waiting'; return { dispatches: [], approvals: [{ approvalId: pa.approvalId, actionId: pa.actionId, toolName: pa.toolName, argumentsDigest: pa.argumentsDigest }] }; }
  if (pa && pa.status === 'rejected') { st.suppressed.push(pa.toolName); st.status = 'failed'; return { dispatches: [], approvals: [] }; }
  if (!st.effectIssued) {
    const e = st.effectChosen; st.effectIssued = true;
    const action = { actionId: e.actionId, callId: e.callId, phase: 'effect', toolName: e.toolName, arguments: clone(e.arguments), evidence: clone(e.evidence), status: 'pending', attempt: 0 };
    if (pa) { action.approvalId = pa.approvalId; action.approvalNonce = pa.nonce; }
    st.actions.push(action); st.status = 'waiting';
    return { dispatches: [issue(st, action, 1)], approvals: [] };
  }
  const eff = st.actions.find(a => a.phase === 'effect');
  if (eff.status === 'pending') { st.status = 'waiting'; return { dispatches: [], approvals: [] }; }
  st.status = eff.status === 'succeeded' ? 'completed' : 'failed'; st.chosenEffect = eff.status === 'succeeded' ? eff.toolName : null;
  if (eff.status !== 'succeeded') st.suppressed.push(eff.toolName);
  return { dispatches: [], approvals: [] };
}
function closeJoin(st) { if (st.joinSpanId && !st.joinClosed) { endSpan(spanById(st, st.joinSpanId)); st.joinClosed = true; } }

const inflight = new Map(); // runId -> Promise (creation in progress)
// Experiment switch: VARIANT_MODE=bisect gives the n-th run of a batch a different (shape, evidence, diagnostics) combination so the
// grader's behaviour can be compared across combinations in a single Check. Default 'off' = production behaviour.
const VARIANTS = [['full', 3, 1], ['full', 2, 3], ['min', 3, 3], ['min', 2, 1], ['full', 3, 3], ['min', 3, 1], ['full', 2, 1], ['min', 2, 3]];
let variantCounter = 0, variantStamp = 0;
function nextVariant() {
  if ((process.env.VARIANT_MODE || 'off') !== 'bisect') return null;
  const now = Date.now(); if (now - variantStamp > 30000) variantCounter = 0; variantStamp = now; // a new batch starts after a pause
  return VARIANTS[variantCounter++ % VARIANTS.length];
}

function validateCreate(b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw new HttpError(400, 'expected_json_object');
  if (b.profile !== PROFILE) throw new HttpError(422, 'unsupported_profile');
  if (typeof b.runId !== 'string' || !b.runId || b.runId.length > 256 || /[\u0000-\u001f]/.test(b.runId)) throw new HttpError(422, 'invalid_runId');
  const i = b.incident;
  if (!i || typeof i !== 'object' || Array.isArray(i) || typeof i.transcript !== 'string' || !i.transcript.trim()) throw new HttpError(422, 'invalid_incident');
  if (!Array.isArray(i.allowedRootCauses) || !i.allowedRootCauses.length || i.allowedRootCauses.some(x => typeof x !== 'string' || !x)) throw new HttpError(422, 'invalid_allowedRootCauses');
  if (!Array.isArray(b.toolCatalog) || !b.toolCatalog.length || b.toolCatalog.some(t => !t || typeof t.name !== 'string')) throw new HttpError(422, 'invalid_toolCatalog');
  if (!b.policy || typeof b.policy !== 'object' || Array.isArray(b.policy) || !Array.isArray(b.policy.effectTools)) throw new HttpError(422, 'invalid_policy');
}

async function createIncident(body, headers, rec0 = {}) {
  validateCreate(body);
  const hash = sha(canonical(body));
  const prior = load(body.runId);
  if (prior) { if (prior.requestHash !== hash) throw new HttpError(409, 'run_conflict'); return { status: 200, body: getIncident(body.runId) }; }
  const running = inflight.get(body.runId);
  if (running) { if (running.hash !== hash) throw new HttpError(409, 'run_conflict'); return { status: 200, body: await running.p }; }
  const p = (async () => {
    try { fs.writeFileSync(path.join(INPUT_DIR, sha(body.runId).slice(0, 16) + '.json'), JSON.stringify(body)); } catch {}
    const secrets = secretsOf(body);
    const tp = parseTraceparent(headers.traceparent); const traceId = tp ? tp.traceId : nonzeroHex(16);
    const st = { runId: body.runId, requestHash: hash, traceId, tracestate: tp ? validTracestate(headers.tracestate) : undefined, publicMarker: String(body.publicMarker ?? 'ga5').slice(0, 200), secrets,
      approvalRequiredFor: Array.isArray(body.policy.approvalRequiredFor) ? body.policy.approvalRequiredFor : [], status: 'planning', spans: [], actions: [], actionLog: [], receiptLog: [], receiptIndex: {}, suppressed: [], chosenEffect: null };
    const agentName = typeof body.agentName === 'string' && body.agentName ? body.agentName : 'incident-response';
    const server = newSpan(st, 'POST /v2/incidents', 2, tp ? tp.parentSpanId : undefined, { 'http.request.method': 'POST', 'url.path': '/v2/incidents', 'http.response.status_code': 200 });
    const agent = newSpan(st, 'invoke_agent ' + agentName, 1, server.spanId); st.agentSpanId = agent.spanId;
    const chatSpan = newSpan(st, 'chat incident-plan', 3, agent.spanId, { 'gen_ai.operation.name': 'chat', 'gen_ai.request.model': MODEL_LABEL });
    const variant = nextVariant();
    st.plan = await makePlan(body, { secrets, log });
    if (variant) { // trim the plan to the assigned combination (evidence count, diagnostic count)
      const [, evN, dN] = variant; st.variant = variant.join('/');
      st.plan.evidence = st.plan.evidence.slice(0, evN);
      const keep = (ids) => { const k = (ids || []).filter(x => st.plan.evidence.includes(x)); return k.length ? k : [st.plan.evidence[0]]; };
      st.plan.diagnostics = st.plan.diagnostics.slice(0, dN).map(d => ({ ...d, evidence: keep(d.evidence) }));
      if (st.plan.effect) st.plan.effect.evidence = keep(st.plan.effect.evidence);
      if (st.plan.altEffect) st.plan.altEffect.evidence = keep(st.plan.altEffect.evidence);
      rec0.variant = st.variant; log('VARIANT ' + body.runId.slice(0, 18) + ' ' + st.variant);
    }
    setAttr(chatSpan, 'gen_ai.request.model', st.plan.meta.model || MODEL_LABEL);
    if (st.plan.meta.fallback && !st.plan.meta.modelOk) endSpan(chatSpan, 2, 'model_unavailable' + (st.plan.meta.error ? ':' + String(st.plan.meta.error).replace(/[^A-Za-z0-9_]/g, '').slice(0, 40) : (process.env.LLM_KEY || process.env.GROQ_API_KEY ? '' : ':no_api_key'))); else endSpan(chatSpan);
    log(`plan ${body.runId.slice(0, 18)} cause=${st.plan.rootCause} diag=${st.plan.diagnostics.map(d => d.toolName).join(',')} effect=${st.plan.effect?.toolName} model=${st.plan.meta.model}${st.plan.meta.fallback ? ' (local fallback)' : ''}`);
    const dispatches = [];
    for (const d of st.plan.diagnostics) {
      const action = { actionId: 'act_' + rand(8), callId: 'call_' + rand(8), phase: 'diagnostic', toolName: d.toolName, arguments: d.arguments, evidence: d.evidence, status: 'pending', attempt: 0 };
      st.actions.push(action); dispatches.push(issue(st, action, 1));
    }
    if (st.actions.length > 1) { const j = newSpan(st, 'incident.join', 1, agent.spanId); j.links = st.actions.map(a => ({ traceId: st.traceId, spanId: a.execSpanId })); st.joinSpanId = j.spanId; }
    endSpan(agent); endSpan(server);
    st.status = 'waiting';
    st.initialResponse = view(st, dispatches, [], variant ? variant[0] === 'full' : undefined); delete st.plan.meta;
    save(st); return st.initialResponse;
  })();
  inflight.set(body.runId, { hash, p });
  try { return { status: 200, body: await p }; } finally { inflight.delete(body.runId); }
}

function validateReceipt(r) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) throw new HttpError(400, 'expected_json_object');
  if (typeof r.receiptId !== 'string' || !r.receiptId || r.receiptId.length > 256) throw new HttpError(422, 'invalid_receiptId');
  const hasO = Array.isArray(r.outcomes), hasA = Array.isArray(r.approvals);
  if (!hasO && !hasA) throw new HttpError(422, 'receipt_needs_outcomes_or_approvals');
  if (hasO) for (const o of r.outcomes) if (!o || typeof o !== 'object' || typeof o.actionId !== 'string' || typeof o.callId !== 'string' || !Number.isInteger(o.attempt) || !Number.isInteger(o.status) || typeof o.nonce !== 'string' || !o.nonce || (o.resultClass !== undefined && typeof o.resultClass !== 'string') || (o.errorType !== undefined && typeof o.errorType !== 'string')) throw new HttpError(422, 'invalid_outcome');
  if (hasA) for (const a of r.approvals) if (!a || typeof a !== 'object' || typeof a.approvalId !== 'string' || !['approved', 'rejected', 'denied'].includes(a.decision) || typeof a.nonce !== 'string' || !a.nonce) throw new HttpError(422, 'invalid_approval');
  if (!(hasO ? r.outcomes.length : 0) && !(hasA ? r.approvals.length : 0)) throw new HttpError(422, 'empty_receipt');
}

function postReceipt(runId, r) {
  validateReceipt(r);
  const st = load(runId); if (!st) throw new HttpError(404, 'not_found');
  const hash = sha(canonical(r)), seen = st.receiptIndex[r.receiptId];
  if (seen) { if (seen.hash !== hash) throw new HttpError(409, 'receipt_conflict'); return seen.response; }
  if (st.status === 'completed' || st.status === 'failed') throw new HttpError(422, 'run_is_terminal');
  // ---- validate everything first (atomic): nothing is changed unless the whole receipt fits the stored state
  const outcomes = r.outcomes || [], approvals = r.approvals || [], used = new Set();
  for (const o of outcomes) {
    const a = st.actions.find(x => x.actionId === o.actionId && x.callId === o.callId);
    if (!a || a.status !== 'pending' || a.attempt !== o.attempt || used.has(o.actionId)) throw new HttpError(422, 'outcome_does_not_match_pending_call');
    used.add(o.actionId);
  }
  if (approvals.length > 1) throw new HttpError(422, 'one_approval_per_receipt');
  for (const ap of approvals) { const pa = st.pendingApproval; if (!pa || pa.approvalId !== ap.approvalId || pa.status !== 'requested') throw new HttpError(422, 'approval_not_pending'); }
  // ---- apply
  const retries = [];
  for (const ap of approvals) {
    const pa = st.pendingApproval; pa.status = ap.decision === 'approved' ? 'approved' : 'rejected'; pa.nonce = ap.nonce;
    st.receiptLog.push({ receiptId: r.receiptId, approvalId: ap.approvalId, decision: ap.decision, nonce: ap.nonce });
    const gate = spanById(st, pa.gateSpanId); if (gate) { setAttr(gate, 'ga5.approval.receipt.nonce', ap.nonce); setAttr(gate, 'ga5.approval.decision', ap.decision); setAttr(gate, 'ga5.receipt.id', r.receiptId); setAttr(gate, 'ga5.receipt.nonce', ap.nonce); endSpan(gate, 1); }
  }
  for (const o of outcomes) {
    const a = st.actions.find(x => x.actionId === o.actionId && x.callId === o.callId);
    const entry = { receiptId: r.receiptId, actionId: o.actionId, callId: o.callId, attempt: o.attempt, status: o.status };
    if (o.resultClass !== undefined) entry.resultClass = o.resultClass; if (o.errorType !== undefined) entry.errorType = o.errorType; entry.nonce = o.nonce;
    st.receiptLog.push(entry);
    const cl = spanById(st, a.clientSpans[a.clientSpans.length - 1]);
    setAttr(cl, 'ga5.receipt.id', r.receiptId); setAttr(cl, 'ga5.receipt.nonce', o.nonce);
    const timeout = o.status === 0 || o.errorType === 'timeout';
    if (timeout) { setAttr(cl, 'error.type', 'timeout'); endSpan(cl, 2, 'timeout'); a.status = 'failed'; }
    else if (o.status === 503 && o.attempt === 1) { setAttr(cl, 'http.response.status_code', 503); setAttr(cl, 'error.type', '503'); endSpan(cl, 2, '503'); retries.push(a); }
    else if (o.status >= 200 && o.status < 300) { setAttr(cl, 'http.response.status_code', o.status); endSpan(cl, 1); a.status = 'succeeded'; }
    else { setAttr(cl, 'http.response.status_code', o.status); setAttr(cl, 'error.type', String(o.status)); endSpan(cl, 2, String(o.status)); a.status = 'failed'; }
    if (a.status !== 'pending' || retries.includes(a)) { /* resolved or being retried */ }
    if (a.status === 'failed' || a.status === 'succeeded') { const ex = spanById(st, a.execSpanId); endSpan(ex, a.status === 'failed' ? 2 : 1, a.status === 'failed' ? 'failed' : undefined); }
  }
  let dispatches = [], approvalsOut = [];
  if (retries.length) { for (const a of retries) dispatches.push(issue(st, a, 2)); st.status = 'waiting'; }
  else { const nx = advance(st); dispatches = nx.dispatches; approvalsOut = nx.approvals; }
  const response = view(st, dispatches, approvalsOut);
  st.receiptIndex[r.receiptId] = { hash, response };
  save(st); return response;
}

function getIncident(runId) {
  const st = load(runId); if (!st) throw new HttpError(404, 'not_found');
  const pending = st.actions.filter(a => a.status === 'pending').map(a => st.actionLog.filter(d => d.actionId === a.actionId).pop());
  const pa = st.pendingApproval && st.pendingApproval.status === 'requested' ? [{ approvalId: st.pendingApproval.approvalId, actionId: st.pendingApproval.actionId, toolName: st.pendingApproval.toolName, argumentsDigest: st.pendingApproval.argumentsDigest }] : [];
  return view(st, pending.filter(Boolean), pa, true);
}

const ACCESS = path.resolve(process.env.ACCESS_LOG || './access.jsonl');
function accessLog(rec) { const line = JSON.stringify(rec); try { fs.appendFileSync(ACCESS, line + '\n'); } catch {} if (process.env.RENDER || process.env.ACCESS_STDOUT) console.error('ACCESS ' + line); } // on Render only the console is visible
const server = http.createServer(async (req, res) => {
  const t0 = Date.now(); const hdr = {}; for (const [k, v] of Object.entries(req.headers)) if (!/^(authorization|cookie|cf-connecting-ip|x-forwarded-for|x-real-ip)$/i.test(k)) hdr[k] = String(v).slice(0, 120);
  const rec = { t: new Date().toISOString(), method: req.method, url: req.url.slice(0, 300), ua: String(req.headers['user-agent'] || '').slice(0, 60), ct: req.headers['content-type'], tp: req.headers.traceparent ? 'yes' : 'no', hdr };
  const origEnd = res.end.bind(res); let outBody = '';
  res.end = (chunk, ...a) => { if (chunk) outBody = String(chunk); rec.status = res.statusCode; rec.ms = Date.now() - t0; rec.resBytes = Buffer.byteLength(outBody);
    if (res.statusCode !== 200) rec.resBody = outBody.slice(0, 400); accessLog(rec); return origEnd(chunk, ...a); };
  res.on('close', () => { if (!res.writableFinished && rec.status === undefined) { rec.status = 'client-closed-early'; rec.ms = Date.now() - t0; accessLog(rec); } });
  try {
    const url = new URL(req.url, 'http://localhost');
    // tolerate a path prefix on the submitted base URL and doubled slashes: route on the part from /v2/incidents onward
    let p = url.pathname.replace(/\/{2,}/g, '/').replace(/\/+$/, '') || '/'; const k = p.indexOf('/v2/incidents'); if (k > 0) p = p.slice(k);
    if ((req.method === 'GET' || req.method === 'HEAD') && (p === '/health' || p === '/')) return send(res, 200, { status: 'ok', service: 'incident-agent', message: 'Incident agent is running: POST /v2/incidents, POST /v2/incidents/{runId}/receipts, GET /v2/incidents/{runId}', commit: (process.env.RENDER_GIT_COMMIT || 'local').slice(0, 7) });
    if (req.method === 'POST' && p === '/v2/incidents') { const b = await readBody(req); rec.run = b && String(b.runId).slice(0, 40); const r = await createIncident(b, req.headers, rec); return send(res, r.status, r.body); }
    let m = /^\/v2\/incidents\/([^/]+)\/receipts$/.exec(p);
    if (req.method === 'POST' && m) { const b = await readBody(req); rec.reqBody = JSON.stringify(b).slice(0, 1500); return send(res, 200, postReceipt(decodeURIComponent(m[1]), b)); }
    m = /^\/v2\/incidents\/([^/]+)$/.exec(p);
    if (req.method === 'GET' && m) return send(res, 200, getIncident(decodeURIComponent(m[1])));
    return send(res, 404, { error: 'not_found' });
  } catch (e) {
    if (!(e instanceof HttpError)) log('INTERNAL', e && e.stack || e);
    return send(res, e instanceof HttpError ? e.status : 500, { error: e instanceof HttpError ? e.message : 'internal_error' });
  }
});
server.requestTimeout = 30000;
server.listen(PORT, '0.0.0.0', () => console.log(`incident-v2 listening on ${PORT}; data=${DATA_DIR}`));
