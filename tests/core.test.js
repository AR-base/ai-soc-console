const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../src/core.js');
const D = require('../src/data.js');

const raw = D.SAMPLE_ALERTS.map(a => JSON.stringify(a));
const parsed = raw.map(r => C.parseAlert(r).alert);
const baseline = C.parseAlert(JSON.stringify(D.BASELINE_DOC)).alert;
const real02 = C.parseAlert(JSON.stringify(D.REAL[1].doc)).alert;
const real03 = C.parseAlert(JSON.stringify(D.REAL[2].doc)).alert;
const defaults = [baseline, real02, real03];                 // the console's starting set: all real
const defaultTokens = C.redactAll(defaults, '', []).tokens;
const tokenOf = (ents, v) => (ents.find(e => e.value === v) || {}).token;

test('parseAlert accepts plain, _source and array forms; rejects junk', () => {
  assert.equal(C.parseAlert(raw[0]).ok, true);
  assert.equal(C.parseAlert(JSON.stringify({ _source: D.SAMPLE_ALERTS[0] })).alert.rule.id, '60204');
  assert.equal(C.parseAlert(JSON.stringify([D.SAMPLE_ALERTS[1]])).alert.rule.id, '60106');
  assert.equal(C.parseAlert('{bad').error, 'invalid_json');
  assert.equal(C.parseAlert('{"a":1}').error, 'no_rule');
  assert.equal(C.parseAlert('x'.repeat(C.MAX_RAW + 1)).error, 'too_large');
  assert.equal(C.parseAlert('   ').error, 'empty');
});

test('Windows entities: hosts, accounts and account SIDs get stable tokens', () => {
  const { entities } = C.redactAll(parsed, '', []);
  assert.equal(tokenOf(entities, 'AI-SOC-WIN11'), 'HOST_1');
  assert.equal(tokenOf(entities, 'DESKTOP-2KUSA93'), 'HOST_3');
  assert.equal(tokenOf(entities, 'labadmin'), 'USER_1');
  assert.equal(tokenOf(entities, 'soc.test'), 'USER_2');
  assert.equal(tokenOf(entities, 'S-1-5-21-3874120598-1294467102-2981557330-1002'), 'SID_2');
  for (const v of ['Administrators', 'DESKTOP-2KUSA93$', 'S-1-5-32-544', 'S-1-5-18', '-', '::1']) {
    assert.equal(tokenOf(entities, v), undefined, v + ' should stay visible');
  }
});

test('no original personal value survives redaction', () => {
  const { redacted } = C.redactAll(parsed, '', []);
  const all = JSON.stringify(redacted);
  for (const v of ['AI-SOC-WIN11', 'DESKTOP-2KUSA93', 'labadmin', 'soc.test', '192.168.56.101', 'ai-soc-server', '2981557330-1002']) {
    assert.equal(all.includes(v), false, v + ' leaked');
  }
  assert.equal(redacted[1].data.win.eventdata.subjectUserName, 'HOST_3$', 'machine account keeps its $');
  assert.equal(redacted[2].data.win.eventdata.targetSid, 'S-1-5-32-544', 'well-known group SID stays');
  assert.match(redacted[1].data.win.system.message, /Account Name: USER_2\./);
  assert.equal(redacted[0].id, '1762679561.402118', 'alert IDs are not mistaken for IPs');
});

test('keeping a value visible does not renumber other tokens', () => {
  const { redacted } = C.redactAll(parsed, '', ['labadmin']);
  assert.equal(redacted[2].data.win.eventdata.subjectUserName, 'labadmin');
  assert.equal(redacted[2].data.win.eventdata.memberSid, 'SID_2');
  assert.equal(redacted[1].data.win.eventdata.targetUserName, 'USER_2');
});

test('tokens stay stable when another incident changes', () => {
  const first = C.redactAll(parsed, '', []);
  const real = JSON.parse(JSON.stringify(D.SAMPLE_ALERTS[0]));
  real.data.win.eventdata.targetUserName = 'mariam';
  real.agent.ip = '192.168.56.150';
  const second = C.redactAll([real, parsed[1], parsed[2]], '', [], first.tokens);
  const tok = v => (second.tokens.find(e => e.value === v) || {}).token;
  assert.equal(tok('soc.test'), 'USER_2', 'existing value keeps its token');
  assert.equal(tok('labadmin'), 'USER_1');
  assert.equal(tok('mariam'), 'USER_3', 'new value gets the next free number');
  assert.equal(tok('192.168.56.150'), 'IP_2');
  assert.equal(second.redacted[1].data.win.eventdata.targetUserName, 'USER_2');
  assert.equal(second.redacted[2].data.win.eventdata.memberSid, tok('S-1-5-21-3874120598-1294467102-2981557330-1002'));
  assert.equal(C.redactAll(parsed, '', [], [{ value: 'x', token: 'BAD' }, null, { value: 1 }]).tokens.length, 8, 'junk in the saved map is ignored');
});

test('custom terms, emails, Linux and Windows profile paths, IP boundaries', () => {
  const a = { rule: { id: '1' }, full_log: 'mail j.doe@esaip.org about Project Orion at 10.0.0.1 not 10.0.0.12 in /home/mlopez/.ssh and C:\\Users\\nandini\\Desktop and C:\\Users\\Public', data: { srcip: '10.0.0.1' } };
  const { redacted, entities } = C.redactAll([a], 'Project Orion', []);
  const log = redacted[0].full_log;
  for (const v of ['j.doe@esaip.org', 'Project Orion', 'mlopez', 'nandini']) assert.equal(log.includes(v), false, v);
  assert.match(log, /at IP_1 not IP_2/);
  assert.match(log, /Users\\Public/);
  assert.ok(entities.some(e => e.type === 'TERM'));
});

test('redaction never cascades into existing tokens', () => {
  const a = { rule: { id: '1' }, data: { srcuser: 'IP' }, full_log: 'user IP from 1.2.3.4' };
  assert.match(C.redactAll([a], '', []).redacted[0].full_log, /^user USER_1 from IP_1$/);
});

test('real baseline alert: Wazuh export parses, nothing personal leaks, every fact in the prepared analysis holds', () => {
  assert.equal(baseline.rule.id, '60122');
  const r = C.redactAll(defaults, '', []);
  const txt = JSON.stringify(r.redacted[0]);
  for (const v of ['DESKTOP-2KUSA93', 'AI-SOC-WIN11', '192.168.56.101', 'ai-soc-server']) assert.equal(txt.includes(v), false, v);
  const states = C.sanitizeAnalysis(D.BASELINE_ANALYSIS).claims.map(c => C.checkClaim(c, r.redacted[0]).state);
  assert.deepEqual(states, ['match', 'match', 'match', 'match', 'match', 'match', 'judgment', 'judgment']);
  assert.equal(C.detectSeconds(baseline), 209);
  assert.match(C.explainAlert(baseline), /3 min 29 s later/);
});

test('real INC-03 alert: display name is redacted, every fact in the prepared analysis holds, gap matches INC-01', () => {
  const r = C.redactAll(defaults, '', []);
  const txt = JSON.stringify(r.redacted[2]);
  for (const v of ['labuser', 'DESKTOP-2KUSA93', '3660433104']) assert.equal(txt.includes(v), false, v);
  const an = C.sanitizeAnalysis(C.redactWith(D.REAL[2].analysis, r.tokens));
  assert.equal(JSON.stringify(an).includes('labuser'), false, 'analysis carries tokens, not names');
  assert.deepEqual(an.claims.map(c => C.checkClaim(c, r.redacted[2]).state), ['match', 'match', 'match', 'match', 'match', 'match', 'match', 'judgment', 'judgment']);
  assert.ok(Math.abs(C.detectSeconds(real03) - C.detectSeconds(baseline)) <= 1, 'constant event-to-alert gap');
});

test('real INC-02 alert: unlock by the same account as INC-03, every fact holds, email never reaches the AI', () => {
  const r = C.redactAll(defaults, '', []);
  const txt = JSON.stringify(r.redacted[1]);
  for (const v of ['example.com', 'lab.user', 'DESKTOP-2KUSA93']) assert.equal(txt.includes(v), false, v);
  assert.equal(r.redacted[1].data.win.eventdata.targetDomainName, 'MicrosoftAccount');
  assert.equal(r.redacted[1].data.win.eventdata.targetUserSid, r.redacted[2].data.win.eventdata.targetSid, 'same SID token links INC-02 and INC-03');
  const an = C.sanitizeAnalysis(C.redactWith(D.REAL[1].analysis, r.tokens));
  assert.deepEqual(an.claims.map(c => C.checkClaim(c, r.redacted[1]).state), ['match', 'match', 'match', 'match', 'match', 'match', 'match', 'judgment', 'judgment']);
  const p = C.buildPrompt({ id: 'INC-02', scenario: 'Unusual access' }, r.redacted[1], []);
  assert.equal(/example\.com|lab\.user|labuser/.test(p), false, 'prompt carries tokens only');
});

test('example analyses: each wrong claim is caught, every true fact matches', () => {
  const live = C.redactAll(parsed, '', [], defaultTokens);    // samples loaded on top of the real token map
  const redacted = live.redacted;
  const expected = [
    ['match', 'match', 'match', 'conflict', 'judgment'],
    ['match', 'match', 'conflict', 'match', 'judgment'],
    ['match', 'match', 'match', 'match', 'conflict', 'judgment']
  ];
  D.EXAMPLE_ANALYSES.forEach((an, i) => {
    const moved = C.retokenize(an, D.SAMPLE_TOKENS, live.tokens);
    const states = C.sanitizeAnalysis(moved).claims.map(c => C.checkClaim(c, redacted[i]).state);
    assert.deepEqual(states, expected[i], 'INC-0' + (i + 1));
  });
});

test('checkClaim handles missing fields, arrays and field-only claims', () => {
  const alert = { rule: { id: '5', groups: ['a', 'b'] } };
  assert.equal(C.checkClaim({ type: 'fact', field: 'data.nope', value: 'x' }, alert).state, 'missing');
  assert.equal(C.checkClaim({ type: 'fact', field: 'rule.groups', value: '' }, alert).state, 'present');
  assert.equal(C.checkClaim({ type: 'fact', field: 'rule.groups', value: 'B' }, alert).state, 'match');
  assert.equal(C.checkClaim({ type: 'fact', field: 'rule.groups[1]', value: 'b' }, alert).state, 'match');
});

test('Windows key fields: group events report the member and the actor', () => {
  const k = C.keyFields(parsed[2]);
  assert.equal(k.eventId, '4732');
  assert.equal(k.group, 'Administrators');
  assert.equal(k.actor, 'labadmin');
  assert.match(k.user, /-1002$/);
  assert.equal(C.keyFields(parsed[0]).srcip, '::1');
  assert.equal(C.keyFields(parsed[1]).logonType, '2');
});

test('time parsing and detection latency', () => {
  assert.equal(C.parseTime('2026-11-08T20:51:36.000+0000') - C.parseTime('2026-11-08T20:48:07.4568230Z'), 208544);
  assert.equal(C.detectSeconds(parsed[0]), 8);
  assert.equal(C.detectSeconds({ timestamp: 'x' }), null);
  assert.equal(C.fmtDuration(209), '3 min 29 s');
  assert.equal(C.fmtDuration(null), '—');
});

test('explainAlert says why the rule fired in plain words', () => {
  const t = C.explainAlert(parsed[0]);
  assert.match(t, /rule 60204/);
  assert.match(t, /event 4625, a failed logon for account soc\.test/);
  assert.match(t, /needs 8 matching events/);
  assert.match(C.explainAlert(parsed[2]), /added to Administrators by labadmin/);
});

test('KPIs, briefing and Team 2 handoff from reviewed incidents', () => {
  const { redacted, tokens } = C.redactAll(defaults, '', []);
  const analyses = D.REAL.map(x => C.redactWith(x.analysis, tokens));
  const rows = defaults.map((alert, i) => {
    const analysis = C.sanitizeAnalysis(analyses[i]);
    const review = { claims: analysis.claims.map((c, n) => ({ status: C.checkClaim(c, redacted[i]).state === 'conflict' ? 'rejected' : (n === 0 ? 'verified' : 'pending') })), options: analysis.response_options.map(() => true), finalSeverity: i === 2 ? 'Critical' : '' };
    const inc = { id: 'INC-0' + (i + 1), scenario: D.SCENARIOS[i].title };
    return { id: inc.id, scenario: inc.scenario, alert, redacted: redacted[i], analysis, review,
      decision: { status: i === 2 ? 'Closed — lab test' : 'Open', note: 'display name change of USER_2 confirmed by Team 1' },
      summary: C.summarize(inc, redacted[i], analysis, review) };
  });
  const k = C.computeKpis(rows, 3);
  assert.equal(k.coverage.value, 3);
  assert.equal(Math.round(k.mttd.seconds), 208);
  assert.equal(k.mttd.constant, true, 'same gap on every alert');
  assert.equal(k.accuracy.verified, 3);
  assert.equal(k.accuracy.rejected, 0);
  assert.equal(k.accuracy.pct, 100);
  assert.equal(k.verification.made, 26);
  assert.equal(k.openHigh.value, 0, 'all three real incidents are Low');
  const b = C.briefing(rows, k, tokens);
  assert.match(b, /alerts for 3 of our 3 scenarios/);
  assert.match(b, /most likely the VM clock/);
  assert.match(b, /display name change of labuser confirmed by Team 1/, 'briefing shows real names for Team 4');
  assert.equal(/USER_\d|HOST_\d|SID_\d/.test(b), false, 'no tokens left in the briefing');
  assert.ok(b.split(/\s+/).length < 380, 'fits in about two minutes');
  const md = C.team2Markdown(rows.map(r => ({ id: r.id, scenario: r.scenario, alert: r.alert })), '2026-11-09 10:00');
  assert.match(md, /\| INC-01 \| Failed logins \| 1794171096\.3404653 \| 60122 /);
  assert.match(md, /\| INC-03 \| Sensitive change \| 1794171099\.3433247 \| 60110 User account changed \| 8 \| 4738 \|/);
});

test('detokenize leaves unknown tokens alone', () => {
  assert.equal(C.detokenize('USER_1 and USER_9', [{ token: 'USER_1', value: 'labadmin' }]), 'labadmin and USER_9');
});

test('sanitizeAnalysis bounds and cleans hostile input', () => {
  const out = C.sanitizeAnalysis({
    severity: 'CRITICAL', attack_technique: { id: '<script>', name: 'x' },
    claims: [{ text: 'a'.repeat(2000), type: 'fact', field: 'data.srcip"; drop', value: 'v' }, 'plain claim'],
    response_options: Array(20).fill({ action: 'do', priority: 'whenever' }),
    hypotheses: [{ text: 'h', likelihood: 'certain' }]
  });
  assert.equal(out.severity, 'Critical');
  assert.equal(out.attack_technique.id, '');
  assert.equal(out.claims[0].text.length, 500);
  assert.equal(out.claims[0].field, '');
  assert.equal(out.claims[1].type, 'inference');
  assert.equal(out.response_options.length, 8);
  assert.equal(out.response_options[0].priority, 'Soon');
  assert.throws(() => C.sanitizeAnalysis([]));
  assert.throws(() => C.sanitizeAnalysis({}));
});

test('extractJson reads fenced and wrapped answers', () => {
  assert.equal(C.extractJson('Sure!\n```json\n{"severity":"Low"}\n```').severity, 'Low');
  assert.equal(C.extractJson('Here: {"severity":"High"} done').severity, 'High');
  assert.throws(() => C.extractJson('no json here'));
});

test('prompt contains only redacted values and the schema', () => {
  const { redacted } = C.redactAll(parsed, '', []);
  const p = C.buildPrompt({ id: 'INC-02', scenario: 'Unusual access' }, redacted[1], [C.contextLine({ id: 'INC-01' }, redacted[0])]);
  for (const v of ['soc.test', 'DESKTOP-2KUSA93', 'AI-SOC-WIN11']) assert.equal(p.includes(v), false, v);
  assert.match(p, /Wazuh band: Low/);
  assert.match(p, /"response_options"/);
  assert.match(p, /INC-01 .*rule 60204/);
});

test('summary uses only verified claims and selected actions', () => {
  const { redacted } = C.redactAll(parsed, '', []);
  const an = C.sanitizeAnalysis(D.EXAMPLE_ANALYSES[1]);
  const review = { claims: [{ status: 'verified' }, { status: 'verified' }, { status: 'rejected' }, { status: 'pending' }, { status: 'unclear' }], options: [true, false, true, false], finalSeverity: 'High', analyst: 'Test' };
  const s = C.summarize({ id: 'INC-02', scenario: 'Unusual access' }, redacted[1], an, review);
  assert.equal(s.verified.length, 2);
  assert.equal(s.rejected[0].actual, '2');
  assert.equal(s.actions.length, 2);
  const md = C.summaryMarkdown(s, '2026-11-09 10:00');
  assert.match(md, /~~It was a Remote Desktop logon/);
  assert.equal(md.includes('soc.test'), false);
});

test('tokenSegments splits tokens, including SIDs, for highlighting', () => {
  assert.deepEqual(C.tokenSegments('from SID_2 to HOST_1.').map(s => !!s.token), [false, true, false, true, false]);
});

test('initial shared case: three real incidents, consistent tokens, nothing personal in analyses', () => {
  const defs = [{ id: 'INC-01', scenario: 'Failed logins' }, { id: 'INC-02', scenario: 'Unusual access' }, { id: 'INC-03', scenario: 'Sensitive change' }];
  const c = C.initialCase(D, defs);
  assert.equal(c.incidents.length, 3);
  assert.deepEqual(c.incidents.map(x => x.analysisSource), ['prepared', 'prepared', 'prepared']);
  assert.deepEqual(c.incidents.map(x => x.analysisFor), ['1794171096.3404653', '1794171099.3436894', '1794171099.3433247']);
  const red = C.redactAll(c.incidents.map(x => C.parseAlert(x.raw).alert), '', [], c.tokens);
  assert.deepEqual(red.tokens, c.tokens, 'loading the case does not change the token map');
  c.incidents.forEach((inc, i) => {
    assert.equal(/labuser|example|DESKTOP-2KUSA93/.test(JSON.stringify(inc.analysis)), false);
    assert.ok(inc.analysis.claims.every(cl => C.checkClaim(cl, red.redacted[i]).state !== 'conflict'));
    assert.equal(inc.review.claims.length, inc.analysis.claims.length);
  });
  assert.ok(JSON.stringify(c).length < 120000, 'fits the 256 KiB document limit with room to spare');
});

test('normalizeIncident and normalizeConfig survive hostile shared data', () => {
  const def = { id: 'INC-02', scenario: 'Unusual access' };
  assert.equal(C.normalizeIncident(null, def), null);
  assert.equal(C.normalizeIncident([], def), null);
  const evil = { raw: 42, analysis: { severity: 'High', claims: [{ text: 'x', type: 'fact', field: 'rule.id', value: '1' }] },
    review: { claims: [{ status: 'owned', note: 'a'.repeat(999) }], options: ['yes'], finalSeverity: 'Apocalyptic', analyst: { x: 1 } },
    t2: { sent: 'true', explanation: 7 }, t4: { status: 'Nuked', owner: 'Team 4 lead' }, id: 'INC-99', analysisSource: '<img>' };
  const n = C.normalizeIncident(evil, def);
  assert.equal(n.id, 'INC-02', 'id comes from the slot, not the document');
  assert.equal(n.raw, '');
  assert.equal(n.review.claims[0].status, 'pending');
  assert.equal(n.review.claims[0].note.length, 300);
  assert.equal(n.review.options.length, 0, 'options follow the analysis');
  assert.equal(n.review.finalSeverity, '');
  assert.equal(n.review.analyst, '');
  assert.equal(n.t2.sent, false);
  assert.equal(n.t4.status, 'Open');
  assert.equal(n.t4.owner, 'Team 4 lead');
  assert.equal(n.analysisSource, 'pasted');
  assert.equal(C.normalizeIncident({ analysis: 'junk' }, def).analysis, null);
  const cfg = C.normalizeConfig({ tokens: [{ value: 'a', token: 'USER_1' }, { value: 'b', token: 'rm -rf' }, null, { value: {}, token: 'HOST_1' }], keep: ['x', 5], customTerms: 9 });
  assert.deepEqual(cfg.tokens, [{ value: 'a', token: 'USER_1' }]);
  assert.deepEqual(cfg.keep, ['x']);
  assert.equal(cfg.customTerms, '');
});

test('direct AI: request shape, reply parsing, error messages, key check', () => {
  const r = C.anthropicRequest('hello', 'claude-haiku-5-5');
  assert.equal(r.url, 'https://api.anthropic.com/v1/messages');
  assert.equal(r.body.model, 'claude-haiku-5-5');
  assert.deepEqual(r.body.messages, [{ role: 'user', content: 'hello' }]);
  assert.equal(C.anthropicRequest('x', 'evil-model').body.model, 'claude-sonnet-5-5', 'unknown model falls back');
  assert.equal(C.anthropicText({ content: [{ type: 'text', text: '{"a":' }, { type: 'tool_use' }, { type: 'text', text: '1}' }] }), '{"a":1}');
  assert.throws(() => C.anthropicText({ content: [] }));
  assert.throws(() => C.anthropicText(null));
  assert.match(C.apiErrorMessage(401, {}), /key was rejected/);
  assert.match(C.apiErrorMessage(400, { error: { message: 'Your credit balance is too low' } }), /no credit/);
  assert.match(C.apiErrorMessage(0), /Could not reach/);
  assert.match(C.apiErrorMessage(529), /busy/);
  assert.equal(C.looksLikeKey('sk-ant-api03-' + 'a'.repeat(30)), true);
  assert.equal(C.looksLikeKey('hello'), false);
  // the analysis path still validates whatever the model returns
  const an = C.sanitizeAnalysis(C.extractJson('Here you go:\n```json\n' + JSON.stringify(D.EXAMPLE_ANALYSES[0]) + '\n```'));
  assert.equal(an.severity, 'Medium');
});
