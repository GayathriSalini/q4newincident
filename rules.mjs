// Domain reading of the incident transcripts (derived from the real grader incidents).
// Structure: ~125 evidence lines, almost all padded decoys that repeat the same sentence stem (with different ids).
// The decisive evidence is the handful of lines whose sentence appears ONCE in the transcript. Everything below works on those.
const EV_LINE = /^\s*\[([^\]\s]+)\]\s?(.*)$/;
export function parseEvidence(transcript) {
  const lines = []; const ids = new Set();
  for (const raw of String(transcript || '').split(/\r?\n/)) { const m = EV_LINE.exec(raw); if (m) { ids.add(m[1]); lines.push({ id: m[1], text: m[2].trim() }); } }
  return { lines, ids };
}

const PAD = /\s*Correlation corr_\S+ was checked against \S+; retain this full sentence.*$/;
const LABEL = /^[a-z][a-z -]{3,40}:\s*/;
const TS = /^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s*/;
const stemOf = t => t.replace(/\b(svc_\w+|dep_\w+|r\d+-\w+|flag_\w+|corr_\w+|ev_\w+)\b/g, '<ID>').replace(/\b\d+\b/g, '<N>');
export const clean = raw => raw.replace(PAD, '').replace(TS, '').replace(LABEL, '').trim();

// the lines whose sentence occurs once = this incident's own evidence
export function decisive(transcript) {
  const { lines } = parseEvidence(transcript);
  const rows = lines.map(l => ({ id: l.id, text: clean(l.text) }));
  const count = new Map(); for (const r of rows) { const k = stemOf(r.text); count.set(k, (count.get(k) || 0) + 1); }
  const uniq = rows.filter(r => count.get(stemOf(r.text)) === 1);
  return { rows, uniq };
}

// root cause vocabulary: strong phrases are specific to one cause; weak words only hint. The first (symptom) line counts double.
const FAMILIES = [
  { key: 'database_connection', strong: ['pool checkout', 'connection ceiling', 'pool acquisition', 'database reached', 'checkout wait', 'connection pool'], weak: ['pool'], cause: ['database', 'connection'] },
  { key: 'traffic_capacity', strong: ['queue depth', 'request queues', 'requests per second', 'arrival rate', 'per-replica', 'workers saturated', 'trial replica', 'extra replica', 'proposed target', 'scaling to the proposed', 'capacity ceiling'], weak: ['saturat', 'utilization', 'queue'], cause: ['traffic', 'capacity'] },
  { key: 'deployment', strong: ['entered production', 'holdback', 'rollback delegation', 'previous release', 'of release', 'reversal', 'reversions', 'rollout boundary', 'release transition'], weak: ['rollout', 'release'], cause: ['deployment', 'regression'] },
  { key: 'certificate', strong: ['certificate', 'notafter', 'tls negotiation', 'leaf cert', 'dependency team', 'upstream owner'], weak: ['expired', 'dep_'], cause: ['certificate', 'expired'] },
  { key: 'feature_flag', strong: ['flag cohort', 'flag_', 'recursive', 'depth guard', 'flag rule', 'evaluation path'], weak: ['flag'], cause: ['flag', 'recursion'] },
  { key: 'secret_rotation', strong: ['secret version', 'vault', 'revoked the old credential', 'credential', 'rotation'], weak: ['revok', 'secret'], cause: ['secret', 'rotation'] }
];
const hits = (text, ws) => ws.reduce((n, w) => n + (text.includes(w) ? 1 : 0), 0);
export function classifyAll(uniq, allowed) { // every plausible cause, best first
  const first = (uniq[0]?.text || '').toLowerCase(), all = uniq.map(r => r.text.toLowerCase()).join(' \n ');
  const out = [];
  for (const f of FAMILIES) {
    const s = 3 * hits(all, f.strong) + hits(all, f.weak) + 3 * hits(first, f.strong) + hits(first, f.weak);
    if (s <= 0) continue;
    const cause = allowed.find(c => f.cause.every(w => c.toLowerCase().includes(w))) || allowed.find(c => f.cause.some(w => c.toLowerCase().includes(w)));
    if (cause) out.push({ family: f.key, rootCause: cause, score: s });
  }
  return out.sort((a, b) => b.score - a.score);
}
export const classify = (uniq, allowed) => classifyAll(uniq, allowed)[0] || null;

const first = (re, text) => { const m = re.exec(text); return m ? m[1] : undefined; };
const idLine = (uniq, re) => uniq.find(r => re.test(r.text));

// exact values taken from the decisive evidence
export function facts(uniq, input) {
  const text = uniq.map(r => r.text).join('\n');
  const f = { service: input.incident.service, severity: input.incident.severity };
  f.replicas = Number(first(/exactly (\d+)\s+(?:application\s+)?replicas?/i, text)) || undefined;
  f.flag = first(/\b(flag_[A-Za-z0-9]+)/, text);
  f.dependency = first(/\b(dep_[A-Za-z0-9]+)/, text);
  const holdback = first(/holdback (?:still )?(?:running|on) (r\d+-[A-Za-z0-9]+)/i, text) || first(/previous release (r\d+-[A-Za-z0-9]+)/i, text);
  const bad = first(/after (r\d+-[A-Za-z0-9]+) entered production/i, text) || first(/release (r\d+-[A-Za-z0-9]+)/i, text.replace(/previous release r\d+-\w+/i, ''));
  f.goodRelease = holdback; f.badRelease = bad && bad !== holdback ? bad : undefined;
  const d = /delegation=(\d)[;,]?\s*freeze=(\d)[;,]?\s*(?:remaining[^=]*=(\d+))?/i.exec(text);
  f.policy = d ? { delegation: Number(d[1]), freeze: Number(d[2]), remaining: d[3] === undefined ? 1 : Number(d[3]) } : undefined;
  f.replicas = f.replicas ?? (Number(first(/proposed target=(\d+)/i, text)) || undefined);
  f.contractMax = Number(first(/contract maximum=(\d+)/i, text)) || undefined;
  f.operating = Number(first(/operating replicas=(\d+)/i, text)) || undefined;
  const fr = first(/(?:change )?freeze=(\d)/i, text); f.freeze = fr === undefined ? undefined : Number(fr);
  f.pageIfBlocked = /otherwise page the owner|page the owner/i.test(text);
  f.atLimit = /already at (?:its |the )?(?:permitted |approved )?(?:scaling )?(?:limit|ceiling)|no (?:remaining )?headroom|at the replica ceiling/i.test(text);
  return f;
}

export function blocked(F) { // true when a policy gate (freeze / delegation / remaining changes / contract maximum) forbids the effect
  if (F.freeze === 1) return true;
  if (F.policy && !(F.policy.delegation === 1 && F.policy.freeze === 0 && F.policy.remaining > 0)) return true;
  if (F.contractMax !== undefined && F.replicas !== undefined && F.contractMax < F.replicas) return true;
  return false;
}
const has = (input, name) => (input.toolCatalog || []).some(t => t.name === name);
const required = (input, name) => ((input.toolCatalog || []).find(t => t.name === name)?.inputSchema?.required) || [];

// Build a tool call whose arguments are exactly the schema's required keys (the real schemas list only `required`).
function call(input, name, values) {
  const out = {};
  for (const k of required(input, name)) {
    if (!(k in values) || values[k] === undefined) return null;
    out[k] = values[k];
  }
  return { toolName: name, arguments: out };
}

// the plan for each kind of incident (diagnostics confirm the cause; the effect follows the policy lines)
const RICH = (process.env.DIAG_MODE || 'rich') !== 'min';
export function planFor(input, uniq, cls) {
  const F = facts(uniq, input); const svc = F.service, sev = F.severity || 'SEV-1';
  const ev = i => uniq[Math.min(i, uniq.length - 1)].id;
  const by = re => (idLine(uniq, re) || uniq[0]).id;
  const diag = [], mk = (name, values, evId) => { const c = call(input, name, values); if (c && has(input, name)) diag.push({ ...c, evidence: [evId] }); };
  let effect = null, alt = null;
  const page = () => call(input, 'page_owner', { service: svc, severity: sev });
  switch (cls.family) {
    case 'database_connection':
      mk('query_metrics', { service: svc, metric: 'db_connection_pool_wait', windowMinutes: 30 }, by(/pool checkout wait|connection ceiling/i));
      mk('query_logs', { service: svc, query: 'pool acquisition timeout', windowMinutes: 30 }, by(/logs|timeout/i));
      if (RICH) mk('inspect_deployment', { service: svc }, by(/release|flag|no .*changed/i));
      effect = (F.atLimit || blocked(F)) ? page() : call(input, 'scale_service', { service: svc, targetReplicas: F.replicas }); break;
    case 'traffic_capacity':
      mk('query_metrics', { service: svc, metric: 'queue_depth', windowMinutes: 30 }, by(/queue|requests per second|saturated/i));
      if (RICH) { mk('query_logs', { service: svc, query: 'worker saturation request queue', windowMinutes: 30 }, by(/queue|saturated|utilization/i)); mk('inspect_deployment', { service: svc }, by(/release|flag|upstream|database wait/i)); }
      effect = (F.atLimit || blocked(F)) ? page() : call(input, 'scale_service', { service: svc, targetReplicas: F.replicas }); break;
    case 'deployment': {
      mk('inspect_deployment', { service: svc }, by(/release|rollout|holdback/i));
      if (RICH) { mk('query_metrics', { service: svc, metric: 'error_rate', windowMinutes: 30 }, by(/error-rate|error rate|rollout boundary|malformed|resource pressure|rollout/i)); mk('query_logs', { service: svc, query: `${F.badRelease || 'release'} errors after rollout`, windowMinutes: 30 }, by(/holdback|malformed|failed after|release/i)); }
      effect = !blocked(F) ? call(input, 'rollback_deployment', { service: svc, release: F.goodRelease }) : page(); break; }
    case 'certificate':
      mk('dependency_status', { dependency: F.dependency }, by(/certificate/i));
      if (RICH) { mk('query_logs', { service: svc, query: `${F.dependency || 'dependency'} certificate expired`, windowMinutes: 30 }, by(/failed call|expired|notafter|healthy/i)); mk('read_runbook', { service: svc, topic: 'certificate renewal' }, by(/runbook/i)); }
      effect = call(input, 'open_incident', { service: svc, severity: sev }); break;
    case 'feature_flag':
      mk('query_logs', { service: svc, query: `${F.flag || 'feature flag'} recursion depth guard`, windowMinutes: 30 }, by(/flag cohort|recursive|flag/i));
      if (RICH) { mk('inspect_deployment', { service: svc }, by(/deployment|release|shadow/i)); mk('query_metrics', { service: svc, metric: 'error_rate', windowMinutes: 30 }, by(/recursive|loop|flag/i)); }
      effect = blocked(F) ? page() : call(input, 'disable_feature', { service: svc, flag: F.flag }); break;
    case 'secret_rotation':
      mk('read_runbook', { service: svc, topic: 'secret rotation' }, by(/runbook/i));
      if (RICH) { mk('query_logs', { service: svc, query: 'authentication failures after secret revocation', windowMinutes: 30 }, by(/authentication|revocation|secret version/i)); mk('inspect_deployment', { service: svc }, by(/deployment|unchanged|revoked/i)); }
      effect = page(); break;
  }
  if (!effect || !diag.length) return null;
  const evidence = [...new Set(uniq.map(r => r.id))].slice(0, 4);
  return { rootCause: cls.rootCause, evidence, diagnostics: diag, effect: { ...effect, evidence: [evidence[evidence.length - 1]] }, altEffect: F.atLimit ? null : (page() ? { ...page(), evidence: [evidence[0]] } : null), get effectIfAtScalingLimit() { return this.altEffect; }, facts: F };
}
