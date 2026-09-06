/**
 * Generate vectors.json from the JavaScript reference (@profullstack/x402-gateway).
 *
 * Every port in this repo runs the same fixtures, so a pass minted in Ruby is
 * read by Go, a robots.txt from Python matches Rust byte for byte, and a 402
 * body from PHP parses to the same object as the reference. Regenerate with
 * `npm run gen` after bumping the reference version in package.json.
 */
import {
  buildOffer,
  clientIp,
  compileCidrs,
  createGateway,
  daysPaid,
  decodePayment,
  expectedFor,
  inCidrs,
  isSpoofedBrowser,
  isTrainingAgent,
  mintPass,
  readPass,
  robotsTxt,
  RETRIEVAL_AGENTS,
  TRAINING_AGENTS,
  METHODS,
} from '@profullstack/x402-gateway';

const SECRET = 'cp_live_test_secret_0123456789';
const PAY_TO = '0xCC3b072391AE7A8d10cF00DdC5F61DB2cA5541E5';
const SITE = 'https://example.com';
const NOW = 1_800_000_000; // 2027-01-15T08:00:00Z

const req = (url, headers = {}, method = 'GET') => new Request(url, { method, headers });

/* ------------------------------------------------------------- passes -- */
const passes = [];
for (const [ref, exp] of [
  ['0xdeadbeef', NOW + 86400],
  [null, NOW + 86400],
  ['nonce-7-days', NOW + 7 * 86400],
]) {
  const p = await mintPass({ secret: SECRET, ref, expiresAt: exp, now: NOW });
  passes.push({ secret: SECRET, ref, iat: NOW, exp, token: p.token });
}
const good = passes[0].token;
const readCases = [
  { token: good, now: NOW, ok: true, claims: { exp: NOW + 86400, iat: NOW, ref: '0xdeadbeef' } },
  { token: good, now: NOW + 86399, ok: true },
  { token: good, now: NOW + 86400, ok: false, why: 'expired at exactly exp' },
  { token: good.slice(0, -1) + (good.endsWith('A') ? 'B' : 'A'), now: NOW, ok: false, why: 'signature tampered' },
  { token: 'cp_' + good.slice(3).replace(/^./, (c) => (c === 'e' ? 'f' : 'e')), now: NOW, ok: false, why: 'payload tampered' },
  { token: good, now: NOW, secret: 'wrong', ok: false, why: 'wrong secret' },
  { token: 'not-a-pass', now: NOW, ok: false },
  { token: 'cp_nodot', now: NOW, ok: false },
  { token: 'cp_.', now: NOW, ok: false },
  { token: '', now: NOW, ok: false },
  { token: 'cp_' + btoa('{"v":2,"exp":9999999999}').replace(/=+$/, '') + '.sig', now: NOW, ok: false, why: 'wrong version, bad sig' },
];
for (const c of readCases) {
  const r = await readPass(c.token, { secret: c.secret ?? SECRET, now: c.now });
  if (Boolean(r) !== c.ok) throw new Error(`readPass mismatch for ${JSON.stringify(c)}`);
  if (r) c.claims = r;
}

/* ------------------------------------------------------------- offers -- */
const offers = [
  { in: { payTo: PAY_TO, priceCents: 100, resource: `${SITE}/crawl`, description: `1440 minutes of crawl access to ${SITE}` } },
  { in: { payTo: PAY_TO, priceCents: 150, resource: `${SITE}/crawl`, description: 'x' } },
  { in: { payTo: PAY_TO, priceCents: 1, resource: `${SITE}/crawl`, description: 'x' } },
  { in: { payTo: PAY_TO, priceCents: 0.5, resource: `${SITE}/crawl`, description: 'x', maxTimeoutSeconds: 60 } },
  { in: { payTo: PAY_TO, priceCents: 700, resource: `${SITE}/crawl?days=7`, description: `10080 minutes of crawl access to ${SITE} (7 × 1440)` } },
].map((o) => ({ ...o, out: buildOffer(o.in) }));

/* ---------------------------------------------------------- payments -- */
const proof = (network, value, nonce = '0x' + '11'.repeat(32), validBefore = NOW + 600) => ({
  x402Version: 2,
  scheme: 'exact',
  network,
  payload: {
    signature: '0x' + 'ab'.repeat(65),
    authorization: {
      from: '0x46E9322933cc873b40535f9574357A97adee6C79',
      to: PAY_TO,
      value: String(value),
      validAfter: '0',
      validBefore: String(validBefore),
      nonce,
    },
  },
});
const b64 = (o) => btoa(JSON.stringify(o));
const offer1 = buildOffer({ payTo: PAY_TO, priceCents: 100, resource: `${SITE}/crawl`, description: `1440 minutes of crawl access to ${SITE}` });
const payments = [
  { header: b64(proof('eip155:8453', 1000000)), decodes: true, network: 'eip155:8453', expected: expectedFor(proof('eip155:8453', 1000000), offer1) },
  { header: b64(proof('EIP155:137', 3000000)), decodes: true, network: 'EIP155:137', expected: expectedFor(proof('EIP155:137', 3000000), offer1), why: 'network compared case-insensitively' },
  { header: b64(proof('eip155:56', 1000000)), decodes: true, network: 'eip155:56', expected: null, why: 'not an offered network' },
  { header: 'not base64 json', decodes: false },
  { header: btoa('[1,2]'), decodes: true, isObject: true, why: 'an array is an object to JSON.parse; expectedFor then finds no network' , expected: null },
  { header: btoa('"str"'), decodes: false, why: 'a string is not an object' },
  { header: '', decodes: false },
  { header: b64(proof('eip155:8453', 1000000)).replace(/\+/g, '-').replace(/\//g, '_'), decodes: true, network: 'eip155:8453', why: 'base64url accepted' },
];
for (const p of payments) {
  const d = decodePayment(p.header);
  if (Boolean(d) !== p.decodes) throw new Error(`decodePayment mismatch ${p.header}`);
}

const days = [
  { value: '1000000', unit: '1000000', maxDays: 30, days: 1 },
  { value: '7000000', unit: '1000000', maxDays: 30, days: 7 },
  { value: '30000000', unit: '1000000', maxDays: 30, days: 30 },
  { value: '31000000', unit: '1000000', maxDays: 30, days: 0, why: 'over maxDays' },
  { value: '1500000', unit: '1000000', maxDays: 30, days: 0, why: 'not a whole multiple' },
  { value: '999999', unit: '1000000', maxDays: 30, days: 0, why: 'underpaid' },
  { value: '0', unit: '1000000', maxDays: 30, days: 0 },
  { value: null, unit: '1000000', maxDays: 30, days: 0 },
  { value: 'abc', unit: '1000000', maxDays: 30, days: 0 },
  { value: '3000000', unit: '1500000', maxDays: 30, days: 2 },
  { value: '1000000', unit: '0', maxDays: 30, days: 0 },
  { value: '123456789012345678901234567890', unit: '1000000', maxDays: 30, days: 0, why: 'bigger than 64 bits, must not overflow' },
  { value: '20000000000000000000', unit: '10000000000000000000', maxDays: 30, days: 2, why: 'bigger than 64 bits, divides exactly' },
];
for (const d of days) {
  let v = null;
  try { v = d.value === null ? null : BigInt(d.value); } catch { v = null; }
  if (v !== null && v <= 0n) v = null;
  const got = daysPaid(v, d.unit, d.maxDays);
  if (got !== d.days) throw new Error(`daysPaid mismatch ${JSON.stringify(d)} got ${got}`);
}

/* ------------------------------------------------------------- agents -- */
const agents = [
  ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)', true],
  ['Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)', true],
  ['CCBot/2.0 (https://commoncrawl.org/faq/)', true],
  ['Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))', true],
  ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot-Extended)', true],
  ['Bytespider; spider-feedback@bytedance.com', true],
  ['gptbot', true, 'case-insensitive'],
  ['Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot', false],
  ['Mozilla/5.0 (compatible; Claude-SearchBot/1.0)', false],
  ['Mozilla/5.0 (compatible; Applebot/0.1; +http://www.apple.com/go/applebot)', false],
  ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', false],
  ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36', false],
  ['', false],
].map(([ua, paid, why]) => ({ ua, training: paid, ...(why ? { why } : {}) }));
for (const a of agents) if (isTrainingAgent(a.ua) !== a.training) throw new Error(`agent mismatch ${a.ua}`);

/* -------------------------------------------------------------- edge -- */
const cidrs = {
  list: ['51.38.0.0/16', '54.38.0.0/16', '10.0.0.1', '192.168.0.0/0', 'garbage', '1.2.3.4/33', '300.1.1.1/8'],
  compiled: compileCidrs(['51.38.0.0/16', '54.38.0.0/16', '10.0.0.1', '192.168.0.0/0', 'garbage', '1.2.3.4/33', '300.1.1.1/8']).map((c) => c.text),
  cases: [
    ['51.38.1.2', true], ['51.39.0.1', true, 'the /0 matches everything'], ['10.0.0.1', true], ['', false], ['nope', false], ['51.38.1.2.3', false],
  ].map(([ip, hit, why]) => ({ ip, hit, ...(why ? { why } : {}) })),
  narrow: {
    list: ['51.38.0.0/16', '10.0.0.1'],
    cases: [['51.38.255.255', true], ['51.39.0.0', false], ['10.0.0.1', true], ['10.0.0.2', false], ['051.038.1.1', true, 'leading zeros are decimal here']].map(([ip, hit, why]) => ({ ip, hit, ...(why ? { why } : {}) })),
  },
};
{
  const c = compileCidrs(cidrs.list);
  for (const k of cidrs.cases) if (inCidrs(k.ip, c) !== k.hit) throw new Error(`cidr mismatch ${k.ip}`);
  const n = compileCidrs(cidrs.narrow.list);
  for (const k of cidrs.narrow.cases) if (inCidrs(k.ip, n) !== k.hit) throw new Error(`narrow cidr mismatch ${k.ip}`);
}

const clientIps = [
  { headers: { 'x-real-ip': ' 9.9.9.9 ' }, ip: '9.9.9.9' },
  { headers: { 'x-real-ip': '9.9.9.9', 'x-forwarded-for': '1.1.1.1' }, ip: '9.9.9.9', why: 'x-real-ip wins' },
  { headers: { 'x-forwarded-for': '1.1.1.1, 2.2.2.2 , 3.3.3.3' }, ip: '3.3.3.3', why: 'last hop, not first' },
  { headers: { 'x-forwarded-for': '1.1.1.1,,' }, ip: '1.1.1.1' },
  { headers: {}, ip: '' },
];
for (const c of clientIps) if (clientIp(req(SITE + '/', c.headers)) !== c.ip) throw new Error(`clientIp mismatch ${JSON.stringify(c)}`);

const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36';
const spoofs = [
  { ua: CHROME, headers: {}, spoofed: true },
  { ua: CHROME, headers: { 'sec-fetch-mode': 'navigate' }, spoofed: false },
  { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0', headers: {}, spoofed: false, why: 'only Chromium is judged' },
  { ua: 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/145.0.0.0 Safari/537.36', headers: {}, spoofed: false, why: 'declares itself' },
  { ua: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/145.0.0.0', headers: {}, spoofed: false },
  { ua: 'MyCrawler/1.0 Chrome/145.0.0.0', headers: {}, spoofed: false, why: '"crawler" declares itself' },
  { ua: 'Chrome/145.0.0.0 Lightpanda/1.0', headers: {}, spoofed: true },
  { ua: '', headers: {}, spoofed: false },
];
for (const s of spoofs) if (isSpoofedBrowser(req(SITE + '/', { 'user-agent': s.ua, ...s.headers })) !== s.spoofed) throw new Error(`spoof mismatch ${s.ua}`);

/* ------------------------------------------------------------- robots -- */
const robots = [
  { in: { siteUrl: SITE } },
  { in: { siteUrl: SITE + '/', disallow: ['/login', '/api/'], allow: ['/api/v1'], sitemap: '', refused: ['AhrefsBot'], comments: ['Training crawlers buy a pass at /crawl', 'Search crawlers are welcome'] } },
  { in: { siteUrl: SITE, path: '/buy', training: ['GPTBot'], retrieval: ['Bingbot'], sitemap: `${SITE}/sm.xml` } },
].map((r) => ({ ...r, out: robotsTxt(r.in) }));

/* ------------------------------------------------------------- handle -- */
const gwOpts = {
  siteUrl: SITE,
  coinpay: { apiKey: SECRET },
  payTo: PAY_TO,
  denyCidrs: ['51.38.0.0/16'],
  chargeSpoofedBrowsers: true,
  openPaths: ['/llms.txt', '/api/public/'],
  exempt: 'session=', // ports: cookie header contains this substring
};
const gw = createGateway({ ...gwOpts, exempt: (r) => (r.headers.get('cookie') ?? '').includes('session=') });
const GPT = agents[0].ua;
const handleCases = [
  { name: 'person passes', url: '/', headers: { 'user-agent': CHROME, 'sec-fetch-mode': 'navigate' } },
  { name: 'no user agent passes', url: '/', headers: {} },
  { name: 'retrieval crawler passes', url: '/', headers: { 'user-agent': agents[7].ua } },
  { name: 'training crawler is charged, JSON', url: '/', headers: { 'user-agent': GPT } },
  { name: 'training crawler is charged, HTML', url: '/some/page?x=1', headers: { 'user-agent': GPT, accept: 'text/html,application/xhtml+xml' } },
  { name: 'training crawler reads robots.txt', url: '/robots.txt', headers: { 'user-agent': GPT } },
  { name: 'training crawler reads security.txt', url: '/security.txt', headers: { 'user-agent': GPT } },
  { name: 'training crawler reads .well-known', url: '/.well-known/security.txt', headers: { 'user-agent': GPT } },
  { name: 'training crawler reads an open path', url: '/llms.txt', headers: { 'user-agent': GPT } },
  { name: 'training crawler reads under an open prefix', url: '/api/public/feeds', headers: { 'user-agent': GPT } },
  { name: 'open prefix is a prefix, not a substring', url: '/api/publicity', headers: { 'user-agent': GPT }, why: '/api/public/ must match the directory only' },
  { name: 'training crawler with a valid pass passes', url: '/', headers: { 'user-agent': GPT, 'x-crawl-pass': good } },
  { name: 'training crawler with a bearer pass passes', url: '/', headers: { 'user-agent': GPT, authorization: `Bearer ${good}` } },
  { name: 'training crawler with a bad pass is charged', url: '/', headers: { 'user-agent': GPT, 'x-crawl-pass': 'cp_bad.bad' } },
  { name: 'training crawler with a session cookie is exempt', url: '/', headers: { 'user-agent': GPT, cookie: 'a=b; session=xyz' } },
  { name: 'spoofed Chrome is charged', url: '/', headers: { 'user-agent': CHROME } },
  { name: 'denied CIDR is 403 even for a person', url: '/', headers: { 'user-agent': CHROME, 'sec-fetch-mode': 'navigate', 'x-forwarded-for': '1.1.1.1, 51.38.9.9' } },
  { name: 'denied CIDR beats the sales page', url: '/crawl', headers: { 'x-real-ip': '51.38.0.1' } },
  { name: 'denied CIDR beats a session', url: '/', headers: { 'user-agent': GPT, cookie: 'session=1', 'x-real-ip': '51.38.0.1' } },
  { name: 'sales page answers a person as HTML', url: '/crawl', headers: { 'user-agent': CHROME, 'sec-fetch-mode': 'navigate', accept: 'text/html' } },
  { name: 'sales page answers curl as JSON', url: '/crawl', headers: { 'user-agent': 'curl/8.0' } },
  { name: 'sales page quotes 7 days', url: '/crawl?days=7', headers: { 'user-agent': 'curl/8.0' } },
  { name: 'sales page clamps days to maxDays', url: '/crawl?days=99', headers: { 'user-agent': 'curl/8.0' } },
  { name: 'sales page treats junk days as one', url: '/crawl?days=abc', headers: { 'user-agent': 'curl/8.0' } },
  { name: 'sales page treats zero days as one', url: '/crawl?days=0', headers: { 'user-agent': 'curl/8.0' } },
  { name: 'proof that is not base64 JSON', url: '/crawl', headers: { 'x-payment': 'nope' } },
  { name: 'proof on an unoffered network', url: '/crawl', headers: { 'x-payment': b64(proof('eip155:56', 1000000)) } },
  { name: 'proof for a fraction of a day', url: '/crawl', headers: { 'x-payment': b64(proof('eip155:8453', 1500000)) } },
];
const handle = [];
for (const c of handleCases) {
  const r = await gw.handle(req(SITE + c.url, c.headers));
  const out = { ...c };
  if (!r) out.pass = true;
  else {
    out.status = r.status;
    const ct = r.headers.get('content-type') ?? '';
    out.contentType = ct.split(';')[0];
    if (ct.startsWith('application/json')) out.body = JSON.parse(await r.text());
    else if (ct.startsWith('text/plain')) out.text = await r.text();
    else out.htmlContains = ['1.00 USD', 'x-crawl-pass', `${SITE}/crawl`];
    out.responseHeaders = { 'cache-control': r.headers.get('cache-control'), vary: r.headers.get('vary') };
  }
  handle.push(out);
}

/* --------------------------------------------- paid path (mock CoinPay) -- */
const gwDisabled = createGateway({ siteUrl: SITE });
const disabled = [];
for (const c of [
  { name: 'disabled gateway still charges, offer is empty', url: '/', headers: { 'user-agent': GPT } },
  { name: 'disabled gateway refuses a proof', url: '/crawl', headers: { 'x-payment': b64(proof('eip155:8453', 1000000)) } },
]) {
  const r = await gwDisabled.handle(req(SITE + c.url, c.headers));
  disabled.push({ ...c, status: r.status, body: JSON.parse(await r.text()) });
}

// The reference's HTTP flow, spelled out so a port can mock CoinPay the same way.
const coinpay = {
  baseUrl: 'https://coinpayportal.com',
  verify: { path: '/api/x402/verify', method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': '<apiKey>' }, body: { payment: '<proof>', expected: '<expectedFor(proof, offer(days))>' }, ok: { valid: true, payment: { from: '<payer>' } }, replayWhen: 'error or reason matches /already used|replay/i' },
  settle: { path: '/api/x402/settle', method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': '<apiKey>' }, body: { payment: '<proof>' }, ok: { settled: true, txHash: '<ref>' }, replayWhen: 'error matches /already settled|already being settled/i' },
  timeoutMs: 20000,
  paid: [
    { name: 'verify valid + settle settled → 200 with a pass for the days paid', proof: proof('eip155:8453', 7000000), verify: { valid: true, payment: { from: '0x46E9322933cc873b40535f9574357A97adee6C79' } }, settle: { settled: true, txHash: '0xtx' }, status: 200, days: 7, minutes: 10080, replayed: false, ref: '0x' + '11'.repeat(32), why: 'ref is the nonce when present' },
    { name: 'verify invalid → 402', proof: proof('eip155:8453', 1000000), verify: { valid: false, error: 'bad signature' }, status: 402, error: 'bad signature' },
    { name: 'settle failed → 402', proof: proof('eip155:8453', 1000000), verify: { valid: true }, settle: { settled: false, error: 'relayer down' }, status: 402, error: 'relayer down' },
    { name: 'replayed proof, settle says already settled → 200 replayed, bounded by validBefore', proof: proof('eip155:8453', 1000000, '0x' + '22'.repeat(32), NOW + 300), verify: { valid: false, error: 'nonce already used' }, settleAgain: { settled: false, error: 'already settled' }, status: 200, days: 1, replayed: true, expiresAt: Math.min(NOW + 86400, NOW + 300 + 86400), why: 'min(now+term, validBefore+term)' },
    { name: 'replayed proof, settle says never paid → 402', proof: proof('eip155:8453', 1000000), verify: { valid: false, error: 'replay' }, settleAgain: { settled: false, error: 'unknown nonce' }, status: 402 },
  ],
};

const vectors = {
  generatedFrom: '@profullstack/x402-gateway@0.3.0',
  constants: { NOW, SECRET, PAY_TO, SITE, TRAINING_AGENTS, RETRIEVAL_AGENTS, METHODS, defaults: { priceCents: 100, currency: 'USD', passMinutes: 1440, maxDays: 30, header: 'x-crawl-pass', path: '/crawl', coinpayBaseUrl: 'https://coinpayportal.com' } },
  passes,
  readPass: readCases,
  offers,
  payments,
  daysPaid: days,
  agents,
  cidrs,
  clientIp: clientIps,
  spoofs,
  robots,
  gateway: gwOpts,
  handle,
  disabled,
  coinpay,
};
process.stdout.write(JSON.stringify(vectors, null, 2) + '\n');
