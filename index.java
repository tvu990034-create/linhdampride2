(() => {
  const app = require('express')();
  const axios = require('axios').default;
  const { createHash } = require('crypto');
  const server = require('http').createServer;
  const env = process.env;
  const RAPIDAPI_SECRET = env.RAPIDAPI_PROXY_SECRET || '';
  const ENFORCE_RAPIDAPI = env.ENFORCE_RAPIDAPI === 'true';
  const AI_API = env.AI_API_URL || 'http://localhost:8000/predict';
  const cache = new Map();

  const EQ = {
    S: (sum, n) => 100 - (sum * 1.8) / (1 + Math.exp(-0.12 * n)),
    G: (len, ops, maps, calls, ai, branches, vars, funcs, loops, conds, asserts, principals, tokens, constants, traits, readOnly, events, postCond, imports) =>
      Math.round(len * 0.8 + ops + maps * 450 + calls * 700 + ai * 150 + branches * 100 + vars * 200 + funcs * 300 + loops * 400 + conds * 250 + asserts * 50 + principals * 75 + tokens * 350 + constants * 100 + traits * 125 + readOnly * 175 + events * 225 + postCond * 275 + imports * 150),
    H: obj => createHash('sha256').update(JSON.stringify(obj)).digest('hex').slice(0, 4),
    T: 5000, M: 25,
    MIN: 100, MAX: 262144,
    W: { critical: 15, high: 9, medium: 4, low: 1 },
    CF: c => c > 0.99 ? 1.1 : c > 0.98 ? 1.0 : 0.95
  };

  const auth = req => !ENFORCE_RAPIDAPI || req.get('x-rapidapi-proxy-secret') === RAPIDAPI_SECRET;
  const sanitize = c => typeof c === 'string' ? c.trim().replace(/[-\u001F\u007F]/g, '') : '';

  const scan = async code => {
    code = sanitize(code);
    if (code.length < EQ.MIN) return { f: [{ id: 'short', m: 'Code too short', sev: 'error' }], s: 0, g: 0 };
    if (code.length > EQ.MAX) return { f: [{ id: 'large', m: 'Code >256KB', sev: 'error' }], s: 0, g: 0 };

    const hash = EQ.H(code);
    const cached = cache.get(hash);
    if (cached && Date.now() - cached.t < EQ.T) return cached.r;

    let findings = [], sum = 0, opsCost = 0;
    const { ctx, flow } = (() => {
      const ctx = { maps: {}, vars: {}, funcs: {}, calls: {}, params: {}, traits: {}, principals: {}, constants: {}, tokens: {}, readOnly: {}, postConditions: 0, dynamicCalls: 0, events: {}, contracts: {}, imports: {}, blockHeights: 0, asContract: 0, folds: 0 };
      const flow = { writes: [], calls: [], branches: [], loops: 0, conds: 0, asserts: 0, principals: 0, overflows: 0, readOnlyCalls: 0, dynamic: 0, eventEmits: 0, contractCreates: 0, importCounts: 0, blockAccess: 0, asContractUses: 0, foldOps: 0 };
      const lines = code.split('\n');
      let depth = 0, current = null, loopDepth = 0, paren = 0, condDepth = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        paren += (line.match(/\(/g)||[]).length - (line.match(/\)/g)||[]).length;

        if (line.startsWith('(define-map')) {
          const name = line.match(/\(define-map\s+(\w+)/)?.[1];
          name && (ctx.maps[name] = { line: i+1, used: false });
        } else if (line.startsWith('(define-data-var')) {
          const name = line.match(/\(define-data-var\s+(\w+)/)?.[1];
          name && (ctx.vars[name] = { line: i+1, used: false });
        } else if (/^\(define-(public|private)\b/.test(line)) {
          const name = line.match(/\(define-(?:public|private)\s+\((\w+)/)?.[1];
          const isPublic = line.startsWith('(define-public');
          const params = line.match(/\(([^)]+)\)/g)?.slice(1) || [];
          name && (current = name, ctx.funcs[name] = { public: isPublic, line: i+1, calls: 0, invoked: 0, params: params.length });
          params.forEach(p => ctx.params[p] = (ctx.params[p]||0) + 1);
        } else if (current && line.includes(')')) {
          depth += (line.match(/\(/g)||[]).length - (line.match(/\)/g)||[]).length;
          if (depth <= 0) current = null;
        } else if (line.startsWith('(define-trait')) {
          const name = line.match(/\(define-trait\s+(\w+)/)?.[1];
          name && (ctx.traits[name] = { line: i+1, used: false });
        } else if (line.startsWith('(define-constant')) {
          const name = line.match(/\(define-constant\s+(\w+)/)?.[1];
          name && (ctx.constants[name] = { line: i+1, used: false });
        } else if (/^\(define-(fungible|non-fungible)-token/.test(line)) {
          const name = line.match(/\(define-(?:fungible|non-fungible)-token\s+(\w+)/)?.[1];
          name && (ctx.tokens[name] = { line: i+1, type: line.includes('fungible')?'ft':'nft', used: false });
        } else if (line.startsWith('(define-read-only')) {
          const name = line.match(/\(define-read-only\s+\((\w+)/)?.[1];
          name && (ctx.readOnly[name] = { line: i+1, used: false });
        }

        if (line.includes('contract-call?')) {
          const target = line.match(/contract-call\?\s*\.([^\s]+)/)?.[1];
          target && (ctx.calls[target] = (ctx.calls[target]||0) + 1);
          current && ctx.funcs[current].calls++;
          ctx.readOnly[target] && flow.readOnlyCalls++;
          (line.includes('get-contracts-owned') || line.includes('dynamic')) && (flow.dynamic++, ctx.dynamicCalls++);
        }

        if (/(var-set|map-set)/.test(line)) flow.writes.push({ type: line.includes('tx-sender')?'tx-sender':'state', line: i+1 });
        if (/contract-call\?\s*[^;]+?(stx-transfer\?|ft-transfer\?|nft-transfer\?)/.test(line)) flow.calls.push({ line: i+1 });
        if (/(if|match|fold|map|filter)/.test(line)) {
          flow.branches.push({ line: i+1, depth: loopDepth });
          /(if|match)/.test(line) && (condDepth++, flow.conds++);
          /fold/.test(line) && (flow.foldOps++, ctx.folds++);
        }
        if (/(fold|map|filter|begin|loop)/.test(line)) { loopDepth++; flow.loops++; }
        if (line.includes(')')) {
          loopDepth = Math.max(0, loopDepth - (line.match(/\)/g)||[]).length + (line.match(/\(/g)||[]).length);
          condDepth = Math.max(0, condDepth - (line.match(/\)/g)||[]).length + (line.match(/\(/g)||[]).length);
        }
        /asserts!/.test(line) && (flow.asserts++);
        /(principal|tx-sender|contract-caller)/.test(line) && (flow.principals++, line.match(/(principal\s+'[^']+')/)?.[1] && (ctx.principals[line.match(/(principal\s+'[^']+')/)[1]] = (ctx.principals[line.match(/(principal\s+'[^']+')/)[1]]||0) + 1));
        /\+\s*[^\(u]/.test(line) || /\*\s*[^\(u]/.test(line) && flow.overflows++;
        line.startsWith('(define-post-condition') && (ctx.postConditions++);
        (/print\s+/.test(line) || /emit-event/.test(line)) && (flow.eventEmits++, (line.match(/print\s+\((\w+)/)?.[1] || line.match(/emit-event\s+(\w+)/)?.[1]) && (ctx.events[line.match(/print\s+\((\w+)/)?.[1] || line.match(/emit-event\s+(\w+)/)?.[1]] = (ctx.events[line.match(/print\s+\((\w+)/)?.[1] || line.match(/emit-event\s+(\w+)/)?.[1]]||0) + 1));
        /deploy-contract/.test(line) && (flow.contractCreates++, line.match(/deploy-contract\s+(\w+)/)?.[1] && (ctx.contracts[line.match(/deploy-contract\s+(\w+)/)[1]] = (ctx.contracts[line.match(/deploy-contract\s+(\w+)/)[1]]||0) + 1));
        /block-height|at-block/.test(line) && (flow.blockAccess++, ctx.blockHeights++);
        /as-contract/.test(line) && (flow.asContractUses++, ctx.asContract++);

        Object.keys(ctx.maps).forEach(n => line.includes(` ${n} `) && (ctx.maps[n].used = true));
        Object.keys(ctx.vars).forEach(n => line.includes(` ${n} `) && (ctx.vars[n].used = true));
        Object.keys(ctx.funcs).forEach(n => line.includes(`(${n}`) && ctx.funcs[n].invoked++);
        Object.keys(ctx.traits).forEach(n => line.includes(`use-trait ${n}`) && (ctx.traits[n].used = true));
        Object.keys(ctx.constants).forEach(n => line.includes(` ${n} `) && (ctx.constants[n].used = true));
        Object.keys(ctx.tokens).forEach(n => line.includes(` ${n} `) && (ctx.tokens[n].used = true));
        Object.keys(ctx.readOnly).forEach(n => line.includes(`(${n}`) && (ctx.readOnly[n].used = true));
      }

      if (paren !== 0 || condDepth !== 0 || loopDepth !== 0) throw new Error('Parse error');
      flow.branches.sort((a,b) => a.line - b.line);
      return { ctx, flow };
    })();

    const detect = () => {
      const list = [];
      flow.calls.forEach(({line}) => {
        const after = code.split('\n').slice(line).join('\n').split(';')[0];
        !/(var-set|map-set)/.test(after) && list.push({ id: 'reentrancy', m: 'External call before state write', sev: 'critical', l: line });
      });
      Object.entries(ctx.funcs).forEach(([name, fn]) => {
        if (name === 'mint' && fn.public) {
          const body = code.split('\n').slice(fn.line).join('\n');
          !/(tx-sender|contract-caller|is-eq)/.test(body) && list.push({ id: 'mint-open', m: 'Public mint without auth', sev: 'critical', l: fn.line });
        }
        fn.invoked === 0 && list.push({ id: 'unused-func', m: `Unused function: ${name}`, sev: 'low', l: fn.line });
        fn.calls > 5 && list.push({ id: 'many-calls', m: `High external call count in ${name}`, sev: 'medium', l: fn.line });
        fn.params > 10 && list.push({ id: 'many-params', m: `Too many params in ${name}`, sev: 'medium', l: fn.line });
        fn.public && !/(tx-sender|contract-caller|is-eq)/.test(code.split('\n').slice(fn.line).join('\n')) && list.push({ id: 'no-auth', m: `Public ${name} lacks auth`, sev: 'critical', l: fn.line });
      });
      /unwrap-(?:err-)?panic/.test(code) && Object.values(ctx.funcs).some(f => f.public) && list.push({ id: 'unwrap-pub', m: 'unwrap-panic in public', sev: 'high' });
      const transfer = code.match(/(ft-transfer\?|nft-transfer\?)\s+[^;]+?tx-sender/);
      transfer && !/try!/.test(code.slice(transfer.index).split(';')[0]) && list.push({ id: 'transfer-risk', m: 'Transfer without try!', sev: 'high' });
      /\/\s+[^u0-9][^)]*/.test(code) && list.push({ id: 'div-user', m: 'Division by user input', sev: 'critical' });
      Object.entries(ctx.maps).forEach(([n, m]) => !m.used && list.push({ id: 'unused-map', m: `Unused map: ${n}`, sev: 'low', l: m.line }));
      Object.entries(ctx.vars).forEach(([n, v]) => !v.used && list.push({ id: 'unused-var', m: `Unused var: ${n}`, sev: 'low', l: v.line }));
      flow.branches.some(b => b.depth > 5) && list.push({ id: 'deep-nest', m: 'Deep nesting', sev: 'medium' });
      flow.loops > 10 && list.push({ id: 'many-loops', m: 'Too many loops', sev: 'medium' });
      flow.conds > 15 && list.push({ id: 'many-conds', m: 'Too many conditions', sev: 'medium' });
      Object.entries(ctx.traits).forEach(([n, t]) => !t.used && list.push({ id: 'unused-trait', m: `Unused trait: ${n}`, sev: 'low', l: t.line }));
      flow.asserts === 0 && Object.keys(ctx.funcs).length > 0 && list.push({ id: 'no-asserts', m: 'No asserts!', sev: 'high' });
      flow.principals > 0 && !/is-eq\s+tx-sender/.test(code) && list.push({ id: 'unchecked-principal', m: 'Principal used without check', sev: 'high' });
      Object.entries(ctx.constants).forEach(([n, c]) => !c.used && list.push({ id: 'unused-const', m: `Unused const: ${n}`, sev: 'low', l: c.line }));
      Object.entries(ctx.tokens).forEach(([n, t]) => !t.used && list.push({ id: 'unused-token', m: `Unused token: ${n}`, sev: 'low', l: t.line }));
      flow.overflows > 0 && list.push({ id: 'overflow-risk', m: 'Arithmetic overflow risk', sev: 'medium' });
      Object.entries(ctx.readOnly).forEach(([n, r]) => !r.used && list.push({ id: 'unused-readonly', m: `Unused read-only: ${n}`, sev: 'low', l: r.line }));
      ctx.postConditions === 0 && Object.values(ctx.funcs).some(f => f.public) && list.push({ id: 'no-postcond', m: 'No post-conditions', sev: 'high' });
      ctx.dynamicCalls > 0 && list.push({ id: 'dynamic-call', m: 'Dynamic contract call', sev: 'critical' });
      flow.eventEmits > 0 && !/print\s+/.test(code) && list.push({ id: 'no-logging', m: 'Events without print', sev: 'medium' });
      flow.contractCreates > 0 && flow.asserts < flow.contractCreates && list.push({ id: 'unsafe-create', m: 'Contract creation without asserts', sev: 'high' });
      ctx.blockHeights > 0 && !/try!|unwrap!/.test(code) && list.push({ id: 'unchecked-block', m: 'Block access without error handling', sev: 'medium' });
      ctx.asContract > 0 && !/ok|err/.test(code) && list.push({ id: 'as-contract-risk', m: 'as-contract without revert', sev: 'critical' });
      ctx.folds > 5 && list.push({ id: 'many-folds', m: 'Too many folds', sev: 'medium' });
      return list;
    };

    const staticFindings = detect();
    staticFindings.forEach(f => {
      const w = EQ.W[f.sev] || 1;
      findings.push({ id: f.id, m: f.m, sev: f.sev, l: f.l || 0 });
      sum += w;
      opsCost += (code.split(f.id.split('-')[0]).length - 1) * 50;
    });

    let aiFindings = [];
    try {
      const { data } = await axios.post(AI_API, { code }, { timeout: 800 });
      aiFindings = (data.vulnerabilities || [])
        .filter(v => v.confidence > 0.98)
        .map(v => {
          const w = v.severity === 'critical' ? 18 : v.severity === 'high' ? 9 : v.severity === 'medium' ? 4 : 1;
          const cf = EQ.CF(v.confidence);
          sum += w * cf;
          return { id: `ai-${v.vulnerability}`, m: `AI: ${v.vulnerability} (${(v.confidence*100).toFixed(0)}%)`, sev: v.severity, l: v.line || 0 };
        });
      findings.push(...aiFindings);
    } catch {}

    const gas = EQ.G(code.length, opsCost, Object.keys(ctx.maps).length, flow.calls.length, aiFindings.length, flow.branches.length, Object.keys(ctx.vars).length, Object.keys(ctx.funcs).length, flow.loops, flow.conds, flow.asserts, flow.principals, Object.keys(ctx.tokens).length, Object.keys(ctx.constants).length, Object.keys(ctx.traits).length, Object.keys(ctx.readOnly).length, Object.keys(ctx.events).length, ctx.postConditions, Object.keys(ctx.imports).length);

    if (gas > 250000) {
      findings.push({ id: 'high-gas', m: `Gas: ${gas}`, sev: 'medium' });
      sum += EQ.W.medium;
    }

    const score = Math.max(0, Math.min(100, Math.round(EQ.S(sum, findings.length))));
    const result = { f: findings, s: score, g: gas };

    if (cache.size >= EQ.M) cache.clear();
    cache.set(hash, { r: result, t: Date.now() });
    return result;
  };

  app.use(require('express').json({ limit: '256kb' }));

  app.post('/scan', async (req, res) => {
    const start = Date.now();
    try {
      if (!auth(req)) return res.status(403).json({ e: 'Forbidden' });
      const { code } = req.body;
      if (!code || typeof code !== 'string') return res.status(400).json({ e: 'Invalid code' });

      const { f, s, g } = await scan(code);
      const report = { f, s, g, t: new Date().toISOString(), v: '1.0.0' };
      report.h = createHash('sha256').update(JSON.stringify(report)).digest('hex');

      const set = (k, env) => res.setHeader(k, env);
      set('Cache-Control', 'no-store');
      set('X-Response-Time', `${Date.now() - start}ms`);
      set('X-Security-Score', s);
      set('X-Finding-Count', f.length);
      set('X-Content-Type-Options', 'nosniff');
      set('X-Frame-Options', 'DENY');
      set('X-XSS-Protection', '1; mode=block');
      set('Referrer-Policy', 'no-referrer');
      set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
      set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
      set('Cross-Origin-Opener-Policy', 'same-origin');

      res.json({ ok: true, report });
    } catch (e) {
      console.error(e);
      res.status(500).json({ e: 'Internal error' });
    }
  });

  app.get('/health', (_, res) => res.json({ ok: true, uptime: Math.round(process.uptime()) }));

  const PORT = env.PORT || 8787;
  server(app).listen(PORT, '0.0.0.0', () => console.log(`Server running on :${PORT}`));
})();