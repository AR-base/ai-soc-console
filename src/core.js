/* Team 3 core: redaction, claim checks, severity, prompt and summary builders.
   Pure functions only — no DOM. Exposed as Core (browser) or module.exports (tests). */
(function (root) {
  'use strict';

  var MAX_RAW = 200000;          // largest alert paste accepted (chars)
  var SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];
  var PRIORITIES = ['Now', 'Soon', 'Later'];
  var LIKELIHOODS = ['High', 'Medium', 'Low'];

  // Generic or system accounts carry no personal data; the AI needs to see them.
  var NON_PERSONAL = new Set(['root', 'daemon', 'nobody', 'sshd', 'www-data', 'system',
    'admin', 'administrator', 'guest', 'test', 'oracle', 'ubuntu', 'user', 'localhost', 'wazuh',
    'administrators', 'users', 'guests', 'remote desktop users', 'builtin', 'workgroup', 'nt authority',
    'local service', 'network service', 'anonymous logon', 'defaultaccount', 'wdagutilityaccount']);
  var USER_FIELDS = new Set(['data.srcuser', 'data.dstuser', 'data.user', 'data.username',
    'data.win.eventdata.targetUserName', 'data.win.eventdata.subjectUserName',
    'syscheck.uname_after', 'syscheck.uname_before', 'syscheck.audit.login_user.name',
    'syscheck.audit.effective_user.name', 'syscheck.audit.user.name',
    'data.win.eventdata.samAccountName', 'data.win.eventdata.memberName', 'data.win.eventdata.displayName']);
  var HOST_FIELDS = new Set(['agent.name', 'manager.name', 'predecoder.hostname', 'data.hostname',
    'data.win.system.computer', 'data.win.eventdata.workstationName', 'hostname']);
  var NON_PERSONAL_PATH_USERS = new Set(['public', 'default', 'default user', 'all users']);
  var NON_PERSONAL_IP = new Set(['127.0.0.1', '0.0.0.0', '255.255.255.255']);

  var RE_IPV4 = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.]*\d)/g;
  var RE_EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  var RE_HOME = /\/home\/([A-Za-z0-9._-]+)/g;
  var RE_WINUSER = /[\\/]Users[\\/]([A-Za-z0-9._ -]{2,40}?)(?=[\\/]|$)/gi;
  var RE_SID = /\bS-1-5-21-\d+-\d+-\d+-\d+\b/g;   // machine/domain account SIDs; well-known SIDs stay visible
  var RE_TOKEN = /\b(?:USER|HOST|IP|EMAIL|SID|TERM)_\d+\b/g;

  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  /* ---------- parsing ---------- */

  // Accepts a Wazuh alert object, a dashboard document ({_source}), or an array (first item).
  function parseAlert(raw) {
    if (typeof raw !== 'string' || !raw.trim()) return { ok: false, error: 'empty' };
    if (raw.length > MAX_RAW) return { ok: false, error: 'too_large' };
    var obj;
    try { obj = JSON.parse(raw); } catch (e) { return { ok: false, error: 'invalid_json' }; }
    if (Array.isArray(obj)) obj = obj[0];
    if (obj && typeof obj === 'object' && obj._source && typeof obj._source === 'object') obj = obj._source;
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { ok: false, error: 'not_object' };
    if (!obj.rule || typeof obj.rule !== 'object') return { ok: false, error: 'no_rule' };
    return { ok: true, alert: obj };
  }

  function getPath(obj, path) {
    if (!path) return undefined;
    var parts = String(path).replace(/\[(\d+)\]/g, '.$1').split('.');
    var cur = obj;
    for (var i = 0; i < parts.length; i++) {
      if (cur == null || typeof cur !== 'object') return undefined;
      if (!Object.prototype.hasOwnProperty.call(cur, parts[i])) return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  var GROUP_EVENTS = new Set(['4727', '4728', '4729', '4731', '4732', '4733', '4754', '4756', '4757']);
  function keyFields(alert) {
    var a = alert || {};
    var mitre = getPath(a, 'rule.mitre.id');
    var ev = str(getPath(a, 'data.win.system.eventID'));
    var ed = function (f) { var v = getPath(a, 'data.win.eventdata.' + f); return v == null || v === '-' ? '' : String(v); };
    var isGroup = GROUP_EVENTS.has(ev);
    var user = getPath(a, 'data.dstuser') || getPath(a, 'data.srcuser') || getPath(a, 'data.user') ||
      (isGroup ? (ed('memberName') || ed('memberSid')) : ed('targetUserName')) || '';
    var src = getPath(a, 'data.srcip') || ed('ipAddress');
    return {
      eventId: ev,
      eventTime: str(getPath(a, 'data.win.system.systemTime')),
      actor: ed('subjectUserName'),
      group: isGroup ? ed('targetUserName') : '',
      logonType: ed('logonType'),
      alertId: str(getPath(a, 'id')),
      time: str(getPath(a, 'timestamp')),
      ruleId: str(getPath(a, 'rule.id')),
      level: num(getPath(a, 'rule.level')),
      description: str(getPath(a, 'rule.description')),
      agent: str(getPath(a, 'agent.name')),
      srcip: str(src),
      user: str(user),
      path: str(getPath(a, 'syscheck.path')),
      mitre: Array.isArray(mitre) ? mitre.join(', ') : str(mitre)
    };
  }
  function str(v) { return v == null ? '' : String(v); }
  function num(v) { var n = Number(v); return isFinite(n) ? n : null; }

  /* ---------- redaction ---------- */

  function walk(node, path, visit) {
    if (typeof node === 'string') { visit(node, path); return; }
    if (Array.isArray(node)) { node.forEach(function (v) { walk(v, path, visit); }); return; }
    if (node && typeof node === 'object') {
      Object.keys(node).forEach(function (k) { walk(node[k], path ? path + '.' + k : k, visit); });
    }
  }

  // Finds personal/confidential values across all alerts and gives each a stable token.
  // Tokens are assigned in discovery order and never renumbered, so keeping a value
  // visible does not shift the others.
  // `prior` is the persisted token map [{value, token}]: a value keeps its token for good,
  // so editing one incident never renumbers the tokens that saved analyses refer to.
  function collectEntities(alerts, customTerms, prior) {
    var found = new Map();             // lower-cased value -> entity present now
    var known = new Map();             // lower-cased value -> {value, type, token}, all time
    var counters = { USER: 0, HOST: 0, IP: 0, EMAIL: 0, SID: 0, TERM: 0 };
    (Array.isArray(prior) ? prior : []).forEach(function (e) {
      if (!e || typeof e.value !== 'string' || typeof e.token !== 'string') return;
      var m = /^([A-Z]+)_(\d{1,6})$/.exec(e.token);
      if (!m || !Object.prototype.hasOwnProperty.call(counters, m[1])) return;
      var key = e.value.toLowerCase();
      if (known.has(key)) return;
      known.set(key, { value: e.value.slice(0, 200), type: m[1], token: e.token });
      counters[m[1]] = Math.max(counters[m[1]], Number(m[2]));
    });
    function add(value, type) {
      var v = String(value).trim();
      if (v.length < 2) return;
      var key = v.toLowerCase();
      if (found.has(key)) return;
      var prev = known.get(key);
      if (prev) { found.set(key, { value: v, type: prev.type, token: prev.token, count: 0 }); return; }
      if (type === 'USER' && (NON_PERSONAL.has(key) || v === '-' || /\$$/.test(v) || /^S-1-/.test(v))) return;
      if (type === 'HOST' && NON_PERSONAL.has(key)) return;
      if (type === 'IP' && NON_PERSONAL_IP.has(v)) return;
      counters[type] += 1;
      var ent = { value: v, type: type, token: type + '_' + counters[type], count: 0 };
      known.set(key, { value: v, type: type, token: ent.token });
      found.set(key, ent);
    }
    (alerts || []).forEach(function (alert) {
      if (!alert) return;
      walk(alert, '', function (s, path) {
        if (USER_FIELDS.has(path)) add(s, 'USER');
        if (HOST_FIELDS.has(path)) add(s, 'HOST');
        var m;
        RE_EMAIL.lastIndex = 0; while ((m = RE_EMAIL.exec(s))) add(m[0], 'EMAIL');
        RE_IPV4.lastIndex = 0; while ((m = RE_IPV4.exec(s))) add(m[0], 'IP');
        RE_HOME.lastIndex = 0; while ((m = RE_HOME.exec(s))) add(m[1], 'USER');
        RE_WINUSER.lastIndex = 0; while ((m = RE_WINUSER.exec(s))) if (!NON_PERSONAL_PATH_USERS.has(m[1].toLowerCase())) add(m[1], 'USER');
        RE_SID.lastIndex = 0; while ((m = RE_SID.exec(s))) add(m[0], 'SID');
      });
    });
    String(customTerms || '').split(/[,\n]/).forEach(function (t) {
      var v = t.trim();
      if (v.length >= 2 && v.length <= 80) add(v, 'TERM');
    });
    return { list: Array.from(found.values()), tokens: Array.from(known.values()).map(function (e) { return { value: e.value, token: e.token }; }) };
  }

  function buildMatcher(entities, keep) {
    var keepSet = new Set((keep || []).map(function (k) { return String(k).toLowerCase(); }));
    var active = entities.filter(function (e) { return !keepSet.has(e.value.toLowerCase()); })
      .sort(function (a, b) { return b.value.length - a.value.length; });
    if (!active.length) return null;
    var parts = active.map(function (e) {
      var body = escapeRe(e.value);
      return e.type === 'IP' ? '(?<![\\d.])' + body + '(?![\\d])' : '(?<![\\w.-])' + body + '(?![\\w-])';
    });
    var byKey = new Map(active.map(function (e) { return [e.value.toLowerCase(), e]; }));
    return { re: new RegExp(parts.join('|'), 'gi'), byKey: byKey };
  }

  // One regex pass with alternation: replacements never cascade into tokens.
  function redactString(s, matcher, counts) {
    if (!matcher) return s;
    return s.replace(matcher.re, function (hit) {
      var e = matcher.byKey.get(hit.toLowerCase());
      if (!e) return hit;
      if (counts) counts[e.token] = (counts[e.token] || 0) + 1;
      return e.token;
    });
  }

  function redactDeep(node, matcher, counts) {
    if (typeof node === 'string') return redactString(node, matcher, counts);
    if (Array.isArray(node)) return node.map(function (v) { return redactDeep(v, matcher, counts); });
    if (node && typeof node === 'object') {
      var out = {};
      Object.keys(node).forEach(function (k) { out[k] = redactDeep(node[k], matcher, counts); });
      return out;
    }
    return node;
  }

  function redactAll(alerts, customTerms, keep, prior) {
    var col = collectEntities(alerts, customTerms, prior);
    var entities = col.list;
    var matcher = buildMatcher(entities, keep);
    var counts = {};
    var redacted = (alerts || []).map(function (a) { return a ? redactDeep(a, matcher, counts) : null; });
    entities.forEach(function (e) { e.count = counts[e.token] || 0; });
    return { entities: entities, redacted: redacted, tokens: col.tokens };
  }

  // Tokenizes any object (e.g. an analysis written with real values) using a saved token map.
  function redactWith(node, tokens) {
    var ents = (Array.isArray(tokens) ? tokens : []).filter(function (t) { return t && typeof t.value === 'string' && /^[A-Z]+_\d+$/.test(t.token); })
      .map(function (t) { return { value: t.value, token: t.token, type: t.token.split('_')[0] }; });
    return redactDeep(node, buildMatcher(ents, []), null);
  }

  // Moves an object written against one token map onto another (via the real values).
  function retokenize(node, fromTokens, toTokens) {
    return redactWith(JSON.parse(detokenize(JSON.stringify(node), fromTokens)), toTokens);
  }

  // Splits text into plain and token segments for highlighted rendering.
  function tokenSegments(text) {
    var out = [], last = 0, m;
    RE_TOKEN.lastIndex = 0;
    while ((m = RE_TOKEN.exec(text))) {
      if (m.index > last) out.push({ t: text.slice(last, m.index) });
      out.push({ t: m[0], token: true });
      last = m.index + m[0].length;
    }
    if (last < text.length) out.push({ t: text.slice(last) });
    return out;
  }

  /* ---------- severity ---------- */

  // Wazuh dashboard bands: 0-6 Low, 7-11 Medium, 12-14 High, 15 Critical.
  function wazuhBand(level) {
    if (level == null || !isFinite(level)) return null;
    if (level >= 15) return 'Critical';
    if (level >= 12) return 'High';
    if (level >= 7) return 'Medium';
    return 'Low';
  }
  function compareSeverity(ai, band) {
    var a = SEVERITIES.indexOf(ai), b = SEVERITIES.indexOf(band);
    if (a < 0 || b < 0) return { diff: null, label: 'No comparison' };
    var d = a - b;
    if (d === 0) return { diff: 0, label: 'AI agrees with the Wazuh level' };
    if (d > 0) return { diff: d, label: 'AI rates ' + d + ' band' + (d > 1 ? 's' : '') + ' above Wazuh — justify or lower' };
    return { diff: d, label: 'AI rates ' + (-d) + ' band' + (d < -1 ? 's' : '') + ' below Wazuh — justify or raise' };
  }

  /* ---------- AI answer ---------- */

  function clip(v, n) { return String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, n); }
  function pick(v, allowed, dflt) {
    var s = clip(v, 20).toLowerCase();
    for (var i = 0; i < allowed.length; i++) if (allowed[i].toLowerCase() === s) return allowed[i];
    return dflt;
  }

  // Tolerant JSON extraction for answers pasted from any AI tool.
  function extractJson(text) {
    var t = String(text || '').trim();
    if (!t) throw new Error('empty');
    if (t.length > MAX_RAW) throw new Error('too_large');
    try { return JSON.parse(t); } catch (e) { /* try harder */ }
    var fence = t.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fence) { try { return JSON.parse(fence[1]); } catch (e) { /* fall through */ } }
    var a = t.indexOf('{'), b = t.lastIndexOf('}');
    if (a >= 0 && b > a) return JSON.parse(t.slice(a, b + 1));
    throw new Error('invalid_json');
  }

  // Validates and bounds an analysis object. Never trusts shape or size.
  function sanitizeAnalysis(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('not_object');
    var arr = function (v, max) { return Array.isArray(v) ? v.slice(0, max) : []; };
    var tech = raw.attack_technique && typeof raw.attack_technique === 'object' ? raw.attack_technique : {};
    var techId = clip(tech.id, 16);
    var out = {
      severity: pick(raw.severity, SEVERITIES, 'Unrated'),
      severity_reason: clip(raw.severity_reason, 600),
      attack_technique: { id: /^T\d{4}(\.\d{3})?$/.test(techId) ? techId : '', name: clip(tech.name, 80) },
      hypotheses: arr(raw.hypotheses, 5).map(function (h) {
        h = h && typeof h === 'object' ? h : { text: h };
        return { text: clip(h.text, 400), likelihood: pick(h.likelihood, LIKELIHOODS, 'Medium') };
      }).filter(function (h) { return h.text; }),
      claims: arr(raw.claims, 12).map(function (c) {
        c = c && typeof c === 'object' ? c : { text: c };
        var field = clip(c.field, 120);
        if (!/^[A-Za-z0-9_.\[\]-]+$/.test(field)) field = '';
        var type = pick(c.type, ['fact', 'inference'], field ? 'fact' : 'inference');
        if (type === 'inference') field = '';
        return { text: clip(c.text, 500), type: type, field: field, value: clip(c.value, 300) };
      }).filter(function (c) { return c.text; }),
      response_options: arr(raw.response_options, 8).map(function (o) {
        o = o && typeof o === 'object' ? o : { action: o };
        return { action: clip(o.action, 300), priority: pick(o.priority, PRIORITIES, 'Soon') };
      }).filter(function (o) { return o.action; }),
      unknowns: arr(raw.unknowns, 6).map(function (u) { return clip(u, 300); }).filter(Boolean)
    };
    if (!out.claims.length && out.severity === 'Unrated') throw new Error('no_content');
    return out;
  }

  /* ---------- claim checks ---------- */

  function norm(v) { return String(v).trim().toLowerCase(); }
  function display(v) {
    if (v === undefined) return '';
    if (typeof v === 'string') return v;
    return JSON.stringify(v);
  }

  // Compares a claim's cited field/value with the redacted alert.
  // States: match, conflict, missing, present (field exists, no value cited), judgment.
  function checkClaim(claim, alert) {
    if (!claim || claim.type !== 'fact' || !claim.field) return { state: 'judgment', actual: '' };
    var v = getPath(alert, claim.field);
    if (v === undefined) return { state: 'missing', actual: '' };
    var actual = display(v);
    if (!claim.value) return { state: 'present', actual: actual };
    var want = norm(claim.value);
    var ok;
    if (Array.isArray(v)) ok = v.some(function (x) { return norm(display(x)) === want || norm(display(x)).indexOf(want) >= 0; });
    else ok = norm(actual) === want || norm(actual).indexOf(want) >= 0;
    return { state: ok ? 'match' : 'conflict', actual: actual };
  }

  /* ---------- prompt ---------- */

  var SCHEMA_EXAMPLE = {
    severity: 'Low | Medium | High | Critical',
    severity_reason: 'one or two sentences',
    attack_technique: { id: 'T1110', name: 'Brute Force' },
    hypotheses: [{ text: 'what may explain the alert', likelihood: 'High | Medium | Low' }],
    claims: [
      { text: 'a fact read from the alert', type: 'fact', field: 'data.srcip', value: 'IP_2' },
      { text: 'a conclusion not directly in the alert', type: 'inference', field: '', value: '' }
    ],
    response_options: [{ action: 'what the SOC should do', priority: 'Now | Soon | Later' }],
    unknowns: ['what the alert cannot tell us']
  };

  function buildPrompt(inc, redacted, context, lang) {
    var k = keyFields(redacted);
    var band = wazuhBand(k.level);
    var lines = [
      'You are assisting a SOC analyst in a university lab exercise (Wazuh SIEM, lab data only).',
      'Analyse the Wazuh alert below. Personal and confidential values were replaced with tokens such as USER_1, HOST_1, IP_1 and SID_1. Keep using the tokens exactly as written and never guess the real values.',
      '',
      'Rules:',
      '1. Every claim of type "fact" must be read from one field of the alert JSON. Give the field as a dot-path (for example data.srcip or rule.groups) and the value you read there.',
      '2. Anything you conclude but cannot read in a single field is type "inference", with an empty field and value.',
      '3. Rate severity as Low, Medium, High or Critical. The Wazuh rule level is ' + (k.level == null ? 'unknown' : k.level) +
        (band ? ' (Wazuh band: ' + band + ')' : '') + '. If you rate differently, say why in severity_reason.',
      '4. Give 2 or 3 hypotheses, including the possibility that this is a lab test event.',
      '5. Give 3 to 5 response options that a SOC command center can act on, each with a priority.',
      '6. List what the alert cannot tell us.',
      '7. Make 5 to 9 claims, mostly facts. Do not invent fields that are not in the JSON.'
    ];
    if (lang === 'fr') lines.push('8. Write every text value in French. Keep the JSON keys and these values in English: Low, Medium, High, Critical, Now, Soon, Later, fact, inference.');
    if (context && context.length) {
      lines.push('', 'Other alerts from the same exercise (context only, do not cite them as fields):');
      context.forEach(function (c) { lines.push('- ' + c); });
    }
    lines.push('', 'Alert ' + inc.id + ' (scenario: ' + inc.scenario + '):', JSON.stringify(redacted, null, 2),
      '', 'Reply with only one JSON object in this shape:', JSON.stringify(SCHEMA_EXAMPLE, null, 2));
    return lines.join('\n');
  }

  function contextLine(inc, redacted) {
    var k = keyFields(redacted);
    var where = k.agent ? ' on ' + k.agent : '';
    return inc.id + ' ' + k.time + ': rule ' + k.ruleId + ' level ' + k.level + where + ' — ' + k.description +
      (k.srcip ? ' (src ' + k.srcip + ')' : '') + (k.user ? ' (user ' + k.user + ')' : '');
  }

  /* ---------- summary ---------- */

  // Builds the one-page incident summary from verified material only.
  function summarize(inc, redacted, analysis, review) {
    var k = keyFields(redacted);
    var band = wazuhBand(k.level);
    var claims = analysis ? analysis.claims : [];
    var rv = review || { claims: [], options: [] };
    var verified = [], rejected = [], open = [];
    claims.forEach(function (c, i) {
      var r = rv.claims[i] || { status: 'pending', note: '' };
      var chk = checkClaim(c, redacted);
      var item = { text: c.text, type: c.type, field: c.field, value: c.value, actual: chk.actual, note: r.note || '' };
      if (r.status === 'verified') verified.push(item);
      else if (r.status === 'rejected') rejected.push(item);
      else open.push(Object.assign(item, { pending: r.status !== 'unclear' }));
    });
    var actions = analysis ? analysis.response_options.filter(function (o, i) { return rv.options[i]; }) : [];
    var order = { Now: 0, Soon: 1, Later: 2 };
    actions.sort(function (a, b) { return order[a.priority] - order[b.priority]; });
    return {
      id: inc.id, scenario: inc.scenario, key: k, band: band,
      aiSeverity: analysis ? analysis.severity : '',
      finalSeverity: rv.finalSeverity || '',
      severityNote: rv.severityNote || (analysis ? analysis.severity_reason : ''),
      technique: analysis ? analysis.attack_technique : null,
      verified: verified, rejected: rejected, open: open,
      unknowns: analysis ? analysis.unknowns : [],
      hypotheses: analysis ? analysis.hypotheses : [],
      actions: actions,
      analyst: rv.analyst || '', decision: rv.decision || '',
      total: claims.length, reviewed: verified.length + rejected.length + open.filter(function (o) { return !o.pending; }).length
    };
  }

  function mdCell(s) { return String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim() || '—'; }
  function mdLine(s) { return String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); }

  function summaryMarkdown(s, stamp) {
    var L = [];
    L.push('# ' + s.id + ' — ' + s.scenario);
    L.push('Team 3 · AI Analysis → Team 4 · Command Center  ');
    L.push('Analyst: ' + (s.analyst || 'not set') + ' · Prepared ' + (stamp || '') + ' · Claims verified ' + s.verified.length + ' of ' + s.total);
    L.push('');
    L.push('| Alert ID | Rule | Wazuh level | Time | Host | Source |');
    L.push('|---|---|---|---|---|---|');
    L.push('| ' + [s.key.alertId, s.key.ruleId + ' ' + s.key.description, s.key.level, s.key.time, s.key.agent, s.key.srcip || s.key.path].map(mdCell).join(' | ') + ' |');
    L.push('');
    L.push('## Severity');
    L.push('**' + (s.finalSeverity || s.aiSeverity || 'Unrated') + '** (final, human-confirmed' + (s.finalSeverity ? '' : ' — not yet confirmed') + '). Wazuh band: ' + (s.band || '—') + '. AI proposed: ' + (s.aiSeverity || '—') + '.');
    if (s.severityNote) L.push('Why: ' + mdLine(s.severityNote));
    if (s.technique && s.technique.id) L.push('ATT&CK: ' + s.technique.id + ' ' + mdLine(s.technique.name) + ' (AI suggestion)');
    L.push('');
    L.push('## Verified findings');
    if (!s.verified.length) L.push('- None verified yet.');
    s.verified.forEach(function (c) {
      L.push('- ' + mdLine(c.text) + (c.field ? ' — evidence `' + c.field + '` = `' + mdLine(c.actual).slice(0, 120) + '`' : ' — analyst judgment') + (c.note ? ' (' + mdLine(c.note) + ')' : ''));
    });
    if (s.rejected.length) {
      L.push('');
      L.push('## AI claims rejected after checking the log');
      s.rejected.forEach(function (c) {
        L.push('- ~~' + mdLine(c.text) + '~~' + (c.field ? ' — log `' + c.field + '` shows `' + (mdLine(c.actual).slice(0, 120) || 'no such field') + '`' : '') + (c.note ? ' (' + mdLine(c.note) + ')' : ''));
      });
    }
    var openItems = s.open.map(function (c) { return mdLine(c.text) + (c.pending ? ' (not reviewed)' : ' (cannot confirm from this alert)'); }).concat(s.unknowns.map(mdLine));
    if (openItems.length) {
      L.push('');
      L.push('## Open questions');
      openItems.forEach(function (t) { L.push('- ' + t); });
    }
    L.push('');
    L.push('## Recommended actions for Team 4');
    if (!s.actions.length) L.push('- None selected yet.');
    s.actions.forEach(function (a) { L.push('- **' + a.priority + '** — ' + mdLine(a.action)); });
    if (s.decision) { L.push(''); L.push('Analyst note: ' + mdLine(s.decision)); }
    L.push('');
    L.push('_Lab data only. Values shown as USER_n, HOST_n, IP_n are redacted tokens. AI output was checked field by field against the Wazuh alert; hypotheses are not verified facts._');
    return L.join('\n');
  }

  /* ---------- time, explanations, KPIs, briefing ---------- */

  // Accepts Wazuh "+0000" offsets and Windows 7-digit fractions.
  function parseTime(s) {
    if (!s) return null;
    var t = String(s).trim().replace(/(\.\d{3})\d+/, '$1').replace(/([+-]\d\d)(\d\d)$/, '$1:$2');
    var ms = Date.parse(t);
    return isFinite(ms) ? ms : null;
  }
  // Seconds from the Windows event to the Wazuh alert; null when either time is missing.
  function detectSeconds(alert) {
    var a = parseTime(getPath(alert, 'timestamp')), e = parseTime(getPath(alert, 'data.win.system.systemTime'));
    if (a == null || e == null) return null;
    return Math.max(0, Math.round((a - e) / 1000));
  }
  function fmtDuration(sec) {
    if (sec == null || !isFinite(sec)) return '—';
    if (sec < 60) return Math.round(sec) + ' s';
    var m = Math.floor(sec / 60), r = Math.round(sec % 60);
    if (m < 60) return m + ' min' + (r ? ' ' + r + ' s' : '');
    return Math.floor(m / 60) + ' h ' + (m % 60) + ' min';
  }

  var EVENT_NAMES = {
    '4624': 'a successful logon', '4625': 'a failed logon', '4634': 'a logoff', '4648': 'a logon with explicit credentials',
    '4672': 'special privileges assigned to a new logon', '4720': 'a user account was created', '4722': 'a user account was enabled',
    '4724': 'a password reset attempt', '4726': 'a user account was deleted', '4728': 'a member added to a global security group',
    '4732': 'a member added to a security-enabled local group', '4733': 'a member removed from a local group',
    '4738': 'a user account was changed', '4740': 'an account was locked out', '1102': 'the audit log was cleared'
  };
  var LOGON_TYPES = { '2': 'interactive', '3': 'network', '4': 'batch', '5': 'service', '7': 'unlock', '8': 'network cleartext', '9': 'new credentials', '10': 'remote interactive (RDP)', '11': 'cached interactive' };

  var EVENT_NAMES_FR = {
    '4624': 'une connexion réussie', '4625': 'un échec de connexion', '4634': 'une déconnexion', '4648': 'une connexion avec identifiants explicites',
    '4672': 'des privilèges spéciaux attribués à une nouvelle session', '4720': 'la création d’un compte utilisateur', '4722': 'l’activation d’un compte utilisateur',
    '4724': 'une tentative de réinitialisation de mot de passe', '4726': 'la suppression d’un compte utilisateur', '4728': 'un membre ajouté à un groupe global de sécurité',
    '4732': 'un membre ajouté à un groupe local de sécurité', '4733': 'un membre retiré d’un groupe local', '4738': 'la modification d’un compte utilisateur',
    '4740': 'le verrouillage d’un compte', '1102': 'l’effacement du journal d’audit'
  };
  var LOGON_TYPES_FR = { '2': 'interactive', '3': 'réseau', '4': 'batch', '5': 'service', '7': 'déverrouillage', '8': 'réseau en clair', '9': 'nouveaux identifiants', '10': 'interactive à distance (RDP)', '11': 'interactive en cache' };
  function explainAlertFr(alert) {
    var k = keyFields(alert);
    var s = 'La règle Wazuh ' + k.ruleId + ' (« ' + k.description + ' », niveau ' + k.level + ') s’est déclenchée' + (k.agent ? ' sur l’agent ' + k.agent : '');
    if (k.eventId) s += ' car le journal Sécurité de Windows a enregistré l’événement ' + k.eventId + (EVENT_NAMES_FR[k.eventId] ? ', ' + EVENT_NAMES_FR[k.eventId] : '');
    s += k.group ? ' (compte ' + k.user + ' ajouté à ' + k.group + ' par ' + (k.actor || 'inconnu') + ')' : (k.user ? ' pour le compte ' + k.user : '');
    if (k.logonType) s += ', type de connexion ' + k.logonType + (LOGON_TYPES_FR[k.logonType] ? ' (' + LOGON_TYPES_FR[k.logonType] + ')' : '');
    var freq = num(getPath(alert, 'rule.frequency'));
    if (freq) s += '. C’est une règle de corrélation : il lui faut ' + freq + ' événements correspondants dans sa fenêtre de temps';
    var lat = detectSeconds(alert);
    if (lat != null) s += '. Windows a enregistré l’événement à ' + k.eventTime.replace('T', ' ').slice(0, 19) + ' UTC ; Wazuh a levé l’alerte ' + fmtDuration(lat) + ' plus tard';
    return s + '.';
  }

  // Plain-language "why this alert fired" for Team 2's handoff.
  function explainAlert(alert, lang) {
    if (lang === 'fr') return explainAlertFr(alert);
    var k = keyFields(alert);
    var parts = ['Wazuh rule ' + k.ruleId + ' ("' + k.description + '", level ' + k.level + ') fired'];
    if (k.agent) parts.push('on agent ' + k.agent);
    if (k.eventId) parts.push('because Windows Security logged event ' + k.eventId + (EVENT_NAMES[k.eventId] ? ', ' + EVENT_NAMES[k.eventId] : ''));
    var who = k.group ? ' (account ' + k.user + ' added to ' + k.group + ' by ' + (k.actor || 'unknown') + ')' :
      (k.user ? ' for account ' + k.user : '');
    var s = parts.join(' ') + who;
    if (k.logonType) s += ', logon type ' + k.logonType + (LOGON_TYPES[k.logonType] ? ' (' + LOGON_TYPES[k.logonType] + ')' : '');
    var freq = num(getPath(alert, 'rule.frequency'));
    if (freq) s += '. It is a correlation rule: it needs ' + freq + ' matching events inside its time window';
    var lat = detectSeconds(alert);
    if (lat != null) s += '. Windows logged the event at ' + k.eventTime.replace('T', ' ').slice(0, 19) + ' UTC; Wazuh raised the alert ' + fmtDuration(lat) + ' later';
    return s + '.';
  }

  // Swaps tokens back to real values (Team 4 acts on real accounts; the AI never saw them).
  function detokenize(text, entities) {
    var map = {};
    (entities || []).forEach(function (e) { map[e.token] = e.value; });
    return String(text == null ? '' : text).replace(RE_TOKEN, function (t) { return Object.prototype.hasOwnProperty.call(map, t) ? map[t] : t; });
  }

  // rows: [{alert, redacted, analysis, review, decision}]
  function computeKpis(rows, total) {
    total = total || rows.length;
    var detected = 0, lat = [], made = 0, reviewed = 0, ver = 0, rej = 0, openHigh = 0, decided = 0;
    rows.forEach(function (r) {
      if (r.alert) detected++;
      var d = r.alert ? detectSeconds(r.alert) : null;
      if (d != null) lat.push(d);
      if (r.analysis) {
        r.analysis.claims.forEach(function (c, i) {
          made++;
          var st = r.review && r.review.claims[i] ? r.review.claims[i].status : 'pending';
          if (st !== 'pending') reviewed++;
          if (st === 'verified') ver++;
          if (st === 'rejected') rej++;
        });
      }
      var sev = (r.review && r.review.finalSeverity) || (r.analysis && r.analysis.severity) || '';
      var status = r.decision && r.decision.status ? r.decision.status : 'Open';
      if (status !== 'Open') decided++;
      if ((sev === 'High' || sev === 'Critical') && (status === 'Open' || status === 'Monitoring')) openHigh++;
    });
    var mttd = lat.length ? lat.reduce(function (a, b) { return a + b; }, 0) / lat.length : null;
    var spread = lat.length > 1 ? Math.max.apply(null, lat) - Math.min.apply(null, lat) : null;
    return {
      coverage: { value: detected, total: total },
      mttd: { seconds: mttd, samples: lat.length, spread: spread, constant: spread != null && spread <= 2 && mttd > 60 },
      accuracy: { verified: ver, rejected: rej, pct: ver + rej ? Math.round(100 * ver / (ver + rej)) : null },
      verification: { reviewed: reviewed, made: made, pct: made ? Math.round(100 * reviewed / made) : null },
      openHigh: { value: openHigh, decided: decided, total: total }
    };
  }

  // French two-minute briefing. `tr` translates UI/analysis strings (tokens kept), then tokens become real names.
  var SEV_FR = { Low: 'faible', Medium: 'moyenne', High: 'élevée', Critical: 'critique', unrated: 'non évaluée', unknown: 'inconnue' };
  function briefingFr(rows, kpi, entities, tr) {
    var L = [], host = '';
    var T = function (x) { return detokenize(tr(x), entities).replace(/[.\s]+$/, ''); };
    rows.some(function (r) { if (r.alert) { host = keyFields(r.alert).agent; } return !!host; });
    L.push('Bonjour. Voici le briefing du centre de commandement de notre SOC Wazuh partagé.');
    L.push('Wazuh a levé des alertes pour ' + kpi.coverage.value + ' de nos ' + kpi.coverage.total + ' scénarios sur le poste Windows ' + (host || 'du labo') +
      (kpi.mttd.seconds != null ? ', en moyenne ' + fmtDuration(kpi.mttd.seconds) + ' après l’enregistrement par Windows' + (kpi.mttd.constant ? ', un écart si constant qu’il vient très probablement de l’horloge de la VM, pas d’une détection lente.' : '.') : '.'));
    rows.forEach(function (r) {
      if (!r.alert) return;
      var s = r.summary;
      if (!s) {
        var kk = keyFields(r.alert);
        L.push(r.id + ', ' + tr(String(r.scenario || '')).toLowerCase() + ' : règle Wazuh ' + kk.ruleId + ' au niveau ' + kk.level + ' (' + (SEV_FR[wazuhBand(kk.level)] || 'non évaluée') + '). L’analyse de l’équipe 3 est en attente.');
        return;
      }
      var sev = s.finalSeverity || s.aiSeverity || 'unrated';
      var first = s.verified[0] ? T(s.verified[0].text) : 'Aucun constat vérifié pour l’instant';
      var st = r.decision && r.decision.status && r.decision.status !== 'Open' ? r.decision.status : '';
      var dec = st ? ' Décision : ' + tr(st).toLowerCase() + (r.decision.note ? ', ' + detokenize(r.decision.note, entities).replace(/[.\s]+$/, '') : '') + '.' : ' Décision en attente.';
      L.push(s.id + ', ' + tr(s.scenario).toLowerCase() + ' : gravité ' + (SEV_FR[sev] || sev) + ' (Wazuh seul disait ' + (SEV_FR[s.band || 'unknown'] || 'inconnue') + '). ' + first + '.' + dec);
    });
    var a = kpi.accuracy;
    L.push('L’IA nous a aidés à trier plus vite, mais nous ne lui avons pas fait confiance aveuglément. Elle a fait ' + kpi.verification.made + ' affirmations ; nous en avons vérifié ' + kpi.verification.reviewed + ' dans le journal, confirmé ' + a.verified + ' et rejeté ' + a.rejected + '.');
    var rejected = null;
    rows.some(function (r) { if (r.summary && r.summary.rejected[0]) { rejected = r.summary.rejected[0]; } return !!rejected; });
    if (rejected) L.push('Par exemple, l’IA a dit : « ' + T(rejected.text) + ' ». Le journal indiquait ' + (rejected.field ? rejected.field + ' = ' + detokenize(rejected.actual || 'rien', entities) : 'autre chose') + ' : cette affirmation n’a donc jamais servi à une décision.');
    L.push(kpi.openHigh.value ? kpi.openHigh.value + ' incident(s) élevé(s) ou critique(s) reste(nt) ouvert(s).' : 'Aucun incident élevé ou critique ne reste ouvert.');
    L.push('Nos priorités : contenir toute modification de droits administrateur en 15 minutes, ajouter une règle qui relie les échecs de connexion à une réussite ultérieure, et garder une vérification humaine sur chaque affirmation de l’IA.');
    return L.join('\n\n');
  }

  // Two-minute spoken briefing (~250 words) from verified material only.
  function briefing(rows, kpi, entities, lang, tr) {
    if (lang === 'fr') return briefingFr(rows, kpi, entities, tr || function (x) { return x; });
    var L = [];
    var host = '';
    rows.some(function (r) { if (r.alert) { host = keyFields(r.alert).agent; } return !!host; });
    L.push('Good morning. This is the Command Center briefing for our shared Wazuh SOC.');
    L.push('Wazuh raised alerts for ' + kpi.coverage.value + ' of our ' + kpi.coverage.total + ' scenarios on the Windows endpoint ' + (host || 'in the lab') +
      (kpi.mttd.seconds != null ? ', on average ' + fmtDuration(kpi.mttd.seconds) + ' after Windows logged the event' + (kpi.mttd.constant ? ', a gap so constant that it is most likely the VM clock, not slow detection.' : '.') : '.'));
    rows.forEach(function (r) {
      if (!r.alert) return;
      var s = r.summary;
      if (!s) {
        var kk = keyFields(r.alert);
        L.push(r.id + ', ' + String(r.scenario || '').toLowerCase() + ': Wazuh rule ' + kk.ruleId + ' at level ' + kk.level + ' (' + (wazuhBand(kk.level) || 'unrated') + '). Team 3 analysis is still pending.');
        return;
      }
      var sev = s.finalSeverity || s.aiSeverity || 'unrated';
      var first = s.verified[0] ? detokenize(s.verified[0].text, entities).replace(/\.$/, '') : 'No finding verified yet';
      var dec = r.decision && r.decision.status && r.decision.status !== 'Open' ? ' Decision: ' + r.decision.status.toLowerCase() + (r.decision.note ? ', ' + detokenize(r.decision.note, entities).replace(/\.$/, '') : '') + '.' : ' Decision pending.';
      L.push(s.id + ', ' + s.scenario.toLowerCase() + ': severity ' + sev + ' (Wazuh alone said ' + (s.band || 'unknown') + '). ' + first + '.' + dec);
    });
    var a = kpi.accuracy;
    L.push('AI helped us triage faster, but we did not trust it blindly. It made ' + kpi.verification.made + ' claims; we checked ' + kpi.verification.reviewed + ' against the log, confirmed ' + a.verified + ' and rejected ' + a.rejected + '.');
    var rejected = null;
    rows.some(function (r) { if (r.summary && r.summary.rejected[0]) { rejected = r.summary.rejected[0]; } return !!rejected; });
    if (rejected) L.push('For example, the AI said: "' + detokenize(rejected.text, entities).replace(/\.$/, '') + '". The log showed ' + (rejected.field ? rejected.field + ' = ' + detokenize(rejected.actual || 'nothing', entities) : 'otherwise') + ', so that claim never reached a decision.');
    L.push(kpi.openHigh.value ? kpi.openHigh.value + ' high or critical incident' + (kpi.openHigh.value > 1 ? 's remain' : ' remains') + ' open.' : 'No high or critical incident is left open.');
    L.push('Our priorities: contain admin-rights changes within 15 minutes, add a rule that links failed logons to a later success, and keep a human check on every AI claim.');
    return L.join('\n\n');
  }

  function team2Markdown(rows, stamp) {
    var L = ['# Team 2 · Detection — test alerts for Team 3', '', 'Prepared ' + (stamp || '') + ' · Source: Windows Security log on the lab endpoint via Wazuh', '',
      '| Incident | Scenario | Alert ID | Rule | Level | Windows event | Alert time (UTC) | Detect time |', '|---|---|---|---|---|---|---|---|'];
    rows.forEach(function (r) {
      if (!r.alert) { L.push('| ' + r.id + ' | ' + r.scenario + ' | not captured | | | | | |'); return; }
      var k = keyFields(r.alert);
      L.push('| ' + [r.id, r.scenario, k.alertId, k.ruleId + ' ' + k.description, k.level, k.eventId, k.time.replace('T', ' ').slice(0, 19), fmtDuration(detectSeconds(r.alert))].map(mdCell).join(' | ') + ' |');
    });
    L.push('', '## Why each alert fired');
    rows.forEach(function (r) { if (r.alert) L.push('- **' + r.id + '** ' + mdLine(r.explanation || explainAlert(r.alert))); });
    L.push('', '_Lab data only. Test events were generated on purpose with the lab account soc.test._');
    return L.join('\n');
  }

  /* ---------- shared case file ---------- */

  var STATUSES = ['pending', 'verified', 'rejected', 'unclear'];
  var DECISIONS = ['Open', 'Contained', 'Monitoring', 'Closed — lab test', 'Closed — false positive'];
  var SOURCES = ['example', 'prepared', 'claude', 'pasted', ''];

  function emptyReview(an) {
    return {
      claims: an ? an.claims.map(function () { return { status: 'pending', note: '' }; }) : [],
      options: an ? an.response_options.map(function () { return false; }) : [],
      finalSeverity: '', severityNote: '', analyst: '', decision: ''
    };
  }
  function emptyT2() { return { explanation: '', shotList: false, shotDoc: false, explained: false, sent: false }; }
  function emptyT4() { return { status: 'Open', owner: '', note: '', at: '' }; }

  // The starting case: real lab alerts where we have them, samples otherwise.
  function initialCase(lab, defs) {
    var src = defs.map(function (d, i) { return lab.REAL && lab.REAL[i] ? lab.REAL[i].doc : lab.SAMPLE_ALERTS[i]; });
    var raws = src.map(function (doc) { return JSON.stringify(doc, null, 2); });
    var alerts = raws.map(function (r) { var p = parseAlert(r); return p.ok ? p.alert : null; });
    var tokens = redactAll(alerts, '', [], []).tokens;
    var incidents = defs.map(function (d, i) {
      var real = lab.REAL && lab.REAL[i];
      var an = sanitizeAnalysis(real ? redactWith(real.analysis, tokens) : retokenize(lab.EXAMPLE_ANALYSES[i], lab.SAMPLE_TOKENS, tokens));
      return {
        id: d.id, scenario: d.scenario, raw: raws[i], redactionChecked: false,
        analysis: an, analysisSource: real ? 'prepared' : 'example', analysisFor: String((src[i]._source || src[i]).id), analysisAt: '',
        review: emptyReview(an), sent: false, sentAt: '', loadedAt: '', t2: emptyT2(), t4: emptyT4()
      };
    });
    return { tokens: tokens, customTerms: '', keep: [], incidents: incidents };
  }

  // Shared documents are written by other viewers: never trust their shape or size.
  function s_(v, n) { return typeof v === 'string' ? v.slice(0, n) : ''; }
  function b_(v) { return v === true; }
  function normalizeIncident(data, def) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
    var an = null;
    if (data.analysis) { try { an = sanitizeAnalysis(data.analysis); } catch (e) { an = null; } }
    var rv = data.review && typeof data.review === 'object' ? data.review : {};
    var base = emptyReview(an);
    var claims = base.claims.map(function (c, i) {
      var r = Array.isArray(rv.claims) && rv.claims[i] && typeof rv.claims[i] === 'object' ? rv.claims[i] : {};
      return { status: STATUSES.indexOf(r.status) >= 0 ? r.status : 'pending', note: s_(r.note, 300) };
    });
    var options = base.options.map(function (o, i) { return Array.isArray(rv.options) ? b_(rv.options[i]) : false; });
    var t2 = data.t2 && typeof data.t2 === 'object' ? data.t2 : {};
    var t4 = data.t4 && typeof data.t4 === 'object' ? data.t4 : {};
    return {
      id: def.id, scenario: def.scenario, raw: s_(data.raw, MAX_RAW), redactionChecked: b_(data.redactionChecked),
      analysis: an, analysisSource: SOURCES.indexOf(data.analysisSource) >= 0 ? data.analysisSource : (an ? 'pasted' : ''),
      analysisFor: s_(data.analysisFor, 64), analysisAt: s_(data.analysisAt, 20),
      review: { claims: claims, options: options, finalSeverity: SEVERITIES.indexOf(rv.finalSeverity) >= 0 ? rv.finalSeverity : '',
        severityNote: s_(rv.severityNote, 600), analyst: s_(rv.analyst, 80), decision: s_(rv.decision, 800) },
      sent: b_(data.sent), sentAt: s_(data.sentAt, 20), loadedAt: s_(data.loadedAt, 20),
      t2: { explanation: s_(t2.explanation, 2000), shotList: b_(t2.shotList), shotDoc: b_(t2.shotDoc), explained: b_(t2.explained), sent: b_(t2.sent) },
      t4: { status: DECISIONS.indexOf(t4.status) >= 0 ? t4.status : 'Open', owner: s_(t4.owner, 80), note: s_(t4.note, 400), at: s_(t4.at, 20) }
    };
  }
  function normalizeConfig(data) {
    data = data && typeof data === 'object' && !Array.isArray(data) ? data : {};
    var tokens = Array.isArray(data.tokens) ? data.tokens.slice(0, 2000).filter(function (t) {
      return t && typeof t.value === 'string' && t.value.length <= 200 && typeof t.token === 'string' && /^[A-Z]+_\d{1,6}$/.test(t.token);
    }).map(function (t) { return { value: t.value, token: t.token }; }) : [];
    return {
      tokens: tokens, customTerms: s_(data.customTerms, 1000),
      keep: Array.isArray(data.keep) ? data.keep.filter(function (k) { return typeof k === 'string'; }).slice(0, 200).map(function (k) { return k.slice(0, 200); }) : []
    };
  }

  /* ---------- direct AI (public website, bring-your-own key) ---------- */

  var MODELS = [
    { id: 'claude-sonnet-5-5', label: 'Claude Sonnet 5.5 · balanced' },
    { id: 'claude-haiku-5-5', label: 'Claude Haiku 5.5 · fastest, cheapest' },
    { id: 'claude-opus-5-5', label: 'Claude Opus 5.5 · most thorough' }
  ];
  function anthropicRequest(prompt, model) {
    var ok = MODELS.some(function (m) { return m.id === model; });
    return {
      url: 'https://api.anthropic.com/v1/messages',
      body: { model: ok ? model : MODELS[0].id, max_tokens: 4000, messages: [{ role: 'user', content: String(prompt).slice(0, MAX_RAW) }] }
    };
  }
  // Joins the text blocks of a Messages API reply.
  function anthropicText(json) {
    if (!json || !Array.isArray(json.content)) throw new Error('no_content');
    var t = json.content.filter(function (b) { return b && b.type === 'text' && typeof b.text === 'string'; }).map(function (b) { return b.text; }).join('');
    if (!t.trim()) throw new Error('no_content');
    return t;
  }
  // Plain-language message for an API failure (status 0 = network/CORS).
  function apiErrorMessage(status, body) {
    var msg = body && body.error && typeof body.error.message === 'string' ? body.error.message : '';
    if (!status) return 'Could not reach the Anthropic API. Check your internet connection and try again.';
    if (status === 401) return 'That API key was rejected. Check it at console.anthropic.com, then paste it again.';
    if (status === 403) return 'This API key is not allowed to use that model. Pick another model or check your key’s permissions.';
    if (status === 404) return 'That model is not available for this key. Pick another model.';
    if (status === 400 && /credit/i.test(msg)) return 'Your API account has no credit left. Add credit at console.anthropic.com, or use “Copy & open Claude”.';
    if (status === 400) return 'The API refused the request' + (msg ? ': ' + msg.slice(0, 160) : '.');
    if (status === 413) return 'The prompt is too large. Turn off the context from other incidents and retry.';
    if (status === 429) return 'Too many requests for this key right now. Wait a minute, then try again.';
    if (status >= 500) return 'The AI service is busy. Try again in a minute.';
    return 'The request failed (HTTP ' + status + ').';
  }
  function looksLikeKey(k) { return /^sk-ant-[A-Za-z0-9_-]{20,}$/.test(String(k || '').trim()); }

  var api = {
    MAX_RAW: MAX_RAW, SEVERITIES: SEVERITIES, PRIORITIES: PRIORITIES,
    parseAlert: parseAlert, getPath: getPath, keyFields: keyFields,
    collectEntities: collectEntities, redactAll: redactAll, redactWith: redactWith, retokenize: retokenize, redactString: redactString, buildMatcher: buildMatcher,
    tokenSegments: tokenSegments, wazuhBand: wazuhBand, compareSeverity: compareSeverity,
    extractJson: extractJson, sanitizeAnalysis: sanitizeAnalysis, checkClaim: checkClaim,
    buildPrompt: buildPrompt, contextLine: contextLine, summarize: summarize, summaryMarkdown: summaryMarkdown,
    parseTime: parseTime, detectSeconds: detectSeconds, fmtDuration: fmtDuration, explainAlert: explainAlert,
    detokenize: detokenize, computeKpis: computeKpis, briefing: briefing, team2Markdown: team2Markdown,
    DECISIONS: DECISIONS, emptyReview: emptyReview, emptyT2: emptyT2, emptyT4: emptyT4,
    initialCase: initialCase, normalizeIncident: normalizeIncident, normalizeConfig: normalizeConfig,
    MODELS: MODELS, anthropicRequest: anthropicRequest, anthropicText: anthropicText, apiErrorMessage: apiErrorMessage, looksLikeKey: looksLikeKey
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.Core = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
