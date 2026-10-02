'use strict';

/**
 * runbook 的每条命令行必须自带密钥来源——*_FILE 部署的"最后一公里"
 *
 * 为什么需要这条闸（不是文风偏好，是两次真实故障的形状）：
 *   ① 备份 cron 写的是 `MONGODB_URI=$(grep ... .env)`，生产口径（.env 不写明文、
 *      密钥只有 ./secrets/<name>）下它每晚 exit 1、零归档，而 cron 的 stderr 没人看；
 *   ② `verify-audit-chain.js` 缺 HMAC_SECRET 时判据是"校验不完整"→ 退出码 2，
 *      手册却写着"要求退出码 0"——命令能跑，结论恒为不完整（见该脚本头注释）。
 * 两者都不是脚本的错，是**命令行没带密钥来源**：脚本侧已经补齐（hydrate +
 * mongo_hydrate_uri，见 src/tests/deploy/backupUriFile.test.js），文档侧需要一个
 * 会失败的闸，否则下一次改手册又会漏掉一条。
 *
 * 判据（"什么算命令行"必须说清楚，否则闸会松到没内容或紧到全是噪音）：
 *   - 围栏代码块内：出现 `node|bash|sh scripts/…` 或 `./scripts/….sh` 即算命令，
 *     位置无关——所以 `# 0 2 * * * … ./scripts/backup-mongo.sh` 这种注释里的
 *     crontab 示例、`cd /opt/xf && …` 复合行都被覆盖；
 *   - 围栏外：抓该行里的每个内联代码 span，span 本身是命令即算命令——所以
 *     「- **处置**：`… node scripts/x.js …`」这种带前导标签的写法不是盲区；
 *     表格行（`|` 起始）不算，那是状态/记录表（如 rollback-drill-record.md 里已完成
 *     演练的行），为了让判据变绿去改写它等于伪造证据。
 *
 * 反面取舍（有意为之，不是遗漏）：文本判据分不出"这样写"与"不要这样写"，所以**反例
 * 不能写成一条可复制的完整命令**。本仓据此把手册里那条 docker compose exec 跑运维脚本
 * 的反例拆成两个 span（`docker compose exec` + 裸文件名）。宁可让反例少一份可粘贴性，
 * 也不给判据开"这条不算"的豁免口——豁免一旦能靠措辞触发，判据就等于没有。
 *
 * 覆盖域 = 说明书（deployment/*.md、docs/incident-response.md、README.md、
 * SECURITY.md、migrations/README.md）；刻意不含**记录**：CHANGELOG.md、
 * deliverables/、docs/adr/、以及 rollback-drill-record.md 的已完成演练表格行。
 * 记录是既成事实的证据，为了过闸去改写它等于伪造现场（同
 * deployment/rollback-drill-record.md 的历史行不改的理由）。adr 里 `npm run
 * rotate:mfa-secret` 这类提法描述的是机制而非操作指令：脚本缺密钥时会响亮地失败
 * （`destructiveGuard` 缺 MONGODB_URI 会打印回退告警、--apply 直接拒绝），
 * 与上面①②的静默失败不同形态，故不在本轮范围内伪装成命令。
 *
 * 前提自证：扫描器不能是空的（命令条数/围栏数/内联数/脚本种数各有下限），
 * 每条通道都必须被一个合成违例点亮，且"不算命令"的排除规则也要反向验证
 * （段落与表格里的同一段命令文本确实不被判为命令）。
 */

const fs = require('fs');
const path = require('path');
const { FILE_BACKED_SECRETS } = require('../../config/secrets');

const ROOT = path.resolve(__dirname, '../../..');

const RUNBOOKS = [
  'README.md',
  'SECURITY.md',
  'migrations/README.md',
  'docs/incident-response.md',
  ...fs
    .readdirSync(path.join(ROOT, 'deployment'))
    .filter((f) => f.endsWith('.md'))
    .map((f) => `deployment/${f}`),
];

/** 除 MONGODB_URI 之外还必需的密钥：手写映射，见 EXTRA_ANCHOR 用例的说明 */
const EXTRA_SECRETS = {
  'verify-audit-chain.js': ['HMAC_SECRET'],
  'resign-audit-hmac.js': ['HMAC_SECRET'],
  'resign-audit-chain-v3.js': ['HMAC_SECRET'],
  'migrate-mfa-secret.js': ['AES_SECRET_KEY'],
  'migrate-pii-encryption.js': ['AES_SECRET_KEY'],
};

const INV_G =
  /(?:^|[\s;&|`(])(?:[A-Za-z_][A-Za-z0-9_]*=\S+[\s;]*)*(?:node|bash|sh)\s+\S*scripts\/([\w.-]+\.(?:js|cjs|sh))\b|(?:^|[\s;&|`(])\.\/scripts\/([\w.-]+\.sh)\b/g;
const FENCE_RE = /^\s*```/;
const SPAN_G = /`([^`\n]+)`/g;
const CONTAINER_PATH_RE = /(?:^|[^A-Za-z0-9_])[A-Z][A-Z0-9_]*_FILE=\/run\/secrets/;
const DOCKER_EXEC_OPS_RE =
  /docker\s+compose\s+exec\b[^\n]*?\b(?:node|bash|sh)\s+\S*scripts\/[\w.-]+\.(?:js|cjs|sh)/;
const APPLY_RE = /(?:^|[\s;])--apply(?=\s|$)/;

const invokedScripts = (text) => {
  INV_G.lastIndex = 0;
  return [...new Set([...text.matchAll(INV_G)].map((m) => m[1] || m[2]))];
};

const hasAssign = (text, name) => new RegExp(`[^A-Za-z0-9_]${name}(?:_FILE)?=\\S`).test(` ${text}`);

const needsCache = new Map();
/** 脚本是否需要外部提供 MONGODB_URI；写入（process.env.MONGODB_URI = …）不算读取 */
const needsMongoUri = (script) => {
  if (!needsCache.has(script)) {
    const file = path.join(ROOT, 'scripts', script);
    if (!fs.existsSync(file)) {
      needsCache.set(script, null);
    } else {
      const src = fs
        .readFileSync(file, 'utf8')
        .split(/\r?\n/)
        .filter((l) => !/process\.env\.MONGODB_URI\s*=[^=]/.test(l))
        .join('\n');
      const needed = script.endsWith('.sh')
        ? /\bMONGODB_URI\b/.test(src) || /\bmongo_hydrate_uri\b/.test(src)
        : /process\.env\.MONGODB_URI\b/.test(src) || /require\([^)]*destructiveGuard/.test(src);
      needsCache.set(script, needed);
    }
  }
  return needsCache.get(script);
};

/** 把一份文档切成"命令行"（含续行合并），返回 [{line,text,fenced,doc}]
 *  只有真的调用了 `scripts/` 下某文件的行才算命令——围栏内的散文注释不是命令 */
const collectCommands = (doc, content) => {
  const found = [];
  let inFence = false;
  let buf = null;
  const flush = () => {
    if (buf) {
      if (invokedScripts(buf.text).length) found.push({ ...buf, doc });
      buf = null;
    }
  };
  content.split(/\r?\n/).forEach((raw, i) => {
    const line = i + 1;
    if (FENCE_RE.test(raw)) {
      flush();
      inFence = !inFence;
      return;
    }
    if (inFence) {
      const cont = /\\\s*$/.test(raw);
      const piece = raw.replace(/\\\s*$/, '');
      if (!buf) buf = { line, text: piece, fenced: true };
      else buf.text += ' ' + piece;
      if (!cont) flush();
      return;
    }
    if (/^\s*\|/.test(raw)) return; // 表格行＝记录/状态，不是指令
    // 围栏外：抓该行里的**每一个**内联代码 span，只要它是命令就算——
    // 「- **处置**：`node scripts/…`」这类带前导标签的写法不留盲区。
    SPAN_G.lastIndex = 0;
    for (const span of raw.matchAll(SPAN_G)) {
      INV_G.lastIndex = 0;
      if (!INV_G.test(span[1])) continue;
      found.push({ line, text: span[1], fenced: false, doc });
    }
  });
  flush();
  return found;
};

const readCommands = (docs = RUNBOOKS) =>
  docs.flatMap((doc) => collectCommands(doc, fs.readFileSync(path.join(ROOT, doc), 'utf8')));

const violations = (cmd) => {
  const { text } = cmd;
  const names = invokedScripts(text).filter((s) => needsMongoUri(s) === true);
  const bad = [];
  if (!names.length) return bad;
  if (!hasAssign(text, 'MONGODB_URI')) bad.push(`缺 MONGODB_URI(_FILE)= … [${names.join(',')}]`);
  for (const s of names) {
    for (const secret of EXTRA_SECRETS[s] || []) {
      if (!hasAssign(text, secret)) bad.push(`缺 ${secret}(_FILE)= …`);
    }
  }
  if (CONTAINER_PATH_RE.test(text)) bad.push('命令行出现 *_FILE=/run/secrets（那是容器内路径）');
  if (DOCKER_EXEC_OPS_RE.test(text))
    bad.push('命令行经 docker compose exec 跑 scripts/（镜像里没有该脚本）');
  if (APPLY_RE.test(text) && !hasAssign(text, 'ALLOWED_SOURCE_DB'))
    bad.push('--apply 未配 ALLOWED_SOURCE_DB');
  return bad;
};

describe('runbook 命令行自带密钥来源', () => {
  const cmds = readCommands();
  const mongoCommands = cmds.filter((c) =>
    invokedScripts(c.text).some((s) => needsMongoUri(s) === true)
  );

  test('前提自证：扫描器不是空的，且每个被调用的脚本文件都存在', () => {
    const unresolved = [...new Set(cmds.flatMap((c) => invokedScripts(c.text)))].filter(
      (s) => needsMongoUri(s) === null
    );
    expect(unresolved).toEqual([]);
    // 下限按当前语料（40 条命令 / 35 条在围栏内 / 5 条行内代码 / 31 条需连库）留 2 成余量：
    // 低于下限说明判据或语料被无声削弱，宁可红一次让人来看，也不放一条静默通过的闸。
    expect(cmds.length).toBeGreaterThanOrEqual(32);
    expect(cmds.filter((c) => c.fenced).length).toBeGreaterThanOrEqual(28);
    expect(cmds.filter((c) => !c.fenced).length).toBeGreaterThanOrEqual(4);
    expect(mongoCommands.length).toBeGreaterThanOrEqual(25);
    const scripts = [...new Set(cmds.flatMap((c) => invokedScripts(c.text)))];
    expect(scripts.filter((s) => needsMongoUri(s) === true).length).toBeGreaterThanOrEqual(6);
    expect(scripts.filter((s) => needsMongoUri(s) === false).length).toBeGreaterThanOrEqual(2);
  });

  test('每一条需要连库的命令行都给了密钥来源', () => {
    const offenders = mongoCommands.flatMap((c) =>
      violations(c).map((why) => `${c.doc}:${c.line} ${why}\n    ${c.text.slice(0, 160)}`)
    );
    expect(offenders).toEqual([]);
  });

  test('--apply 通道确实在跑（语料里有 --apply 命令，且都带 ALLOWED_SOURCE_DB）', () => {
    const applies = mongoCommands.filter((c) => APPLY_RE.test(c.text));
    expect(applies.length).toBeGreaterThanOrEqual(3);
    const offenders = applies
      .filter((c) => !hasAssign(c.text, 'ALLOWED_SOURCE_DB'))
      .map((c) => `${c.doc}:${c.line} ${c.text.slice(0, 200)}`);
    expect(offenders).toEqual([]);
  });

  test('真实文件减法：抹掉手册里任一密钥前缀，对应通道必须点亮', () => {
    // 不是"合成样例只匹配合成写法"：拿真实命令行原文，逐个删掉前缀再喂回同一条通道。
    const names = ['MONGODB_URI', ...new Set(Object.values(EXTRA_SECRETS).flat())];
    for (const name of names) {
      const real = mongoCommands.filter((c) => hasAssign(c.text, name));
      expect(real.length).toBeGreaterThanOrEqual(name === 'MONGODB_URI' ? 20 : 2);
      for (const c of real) {
        const stripped = c.text.replace(new RegExp(`\\b${name}(?:_FILE)?=\\S+`, 'g'), '');
        expect(violations({ text: stripped, doc: c.doc, line: c.line }).join('\n')).toContain(
          `缺 ${name}`
        );
      }
    }
  });

  test('需求映射的名字确实是 FILE_BACKED_SECRETS 的成员（改名即红）', () => {
    for (const [script, secrets] of Object.entries(EXTRA_SECRETS)) {
      const src = fs.readFileSync(path.join(ROOT, 'scripts', script), 'utf8');
      for (const secret of secrets) {
        expect(FILE_BACKED_SECRETS).toContain(secret);
        // 锚点只防"映射与脚本说法脱节"（改名/typo），不证明需求本身仍存在：
        // 真正的需求验证是行为级的，见 src/tests/deploy/* 与 backupUriFile.test.js。
        expect(src).toContain(secret);
      }
    }
  });

  test('反向自证：合成违例被各自的通道点亮', () => {
    const cases = [
      ['node scripts/verify-audit-chain.js', /缺 MONGODB_URI/],
      [
        'MONGODB_URI_FILE=./secrets/mongodb_uri node scripts/verify-audit-chain.js',
        /缺 HMAC_SECRET/,
      ],
      [
        'MONGODB_URI_FILE=./secrets/mongodb_uri node scripts/migrate-mfa-secret.js --dry-run',
        /缺 AES_SECRET_KEY/,
      ],
      [
        'MONGODB_URI_FILE=/run/secrets/mongodb_uri HMAC_SECRET_FILE=/run/secrets/hmac_secret node scripts/verify-audit-chain.js',
        /容器内路径/,
      ],
      [
        'MONGODB_URI_FILE=./secrets/mongodb_uri HMAC_SECRET_FILE=./secrets/hmac_secret node scripts/verify-audit-chain.js --apply',
        /ALLOWED_SOURCE_DB/,
      ],
      [
        'MONGODB_URI_FILE=./secrets/mongodb_uri HMAC_SECRET_FILE=./secrets/hmac_secret docker compose exec -T app node scripts/verify-audit-chain.js',
        /docker compose exec/,
      ],
      ['cd /opt/xf && ./scripts/backup-mongo.sh ./backups', /缺 MONGODB_URI/],
    ];
    for (const [text, re] of cases) {
      const bad = violations({ text });
      expect(bad.join('\n')).toMatch(re);
    }
  });

  test('排除规则是真的：表格行与裸文件指称不算命令，而散文字里的命令 span 算（不留盲区）', () => {
    const doc = [
      '| 步骤 | `node scripts/verify-audit-chain.js` | ☑ |', // 表格行＝记录，非指令
      '> 引用：`scripts/migrate-mfa-secret.js`（AES）。', // 裸文件指称，无解释器
      '手册里带标签的写法：`MONGODB_URI_FILE=./s/mongodb_uri HMAC_SECRET_FILE=./s/hmac_secret node scripts/verify-audit-chain.js` 必须给全前缀',
    ].join('\n');
    const cmds2 = collectCommands('synthetic.md', doc);
    expect(cmds2.map((c) => c.line)).toEqual([3]);
    expect(cmds2[0].fenced).toBe(false);
    expect(violations(cmds2[0])).toEqual([]);
  });

  test('围栏内位置无关：注释形态的 crontab 示例同样是受检命令', () => {
    const doc = [
      '```bash',
      '# 0 2 * * * cd /opt/xf && ./scripts/backup-mongo.sh ./backups',
      '```',
    ].join('\n');
    const cmds2 = collectCommands('synthetic.md', doc);
    expect(cmds2).toHaveLength(1);
    expect(violations(cmds2[0]).join('\n')).toMatch(/缺 MONGODB_URI/);
    // 真实语料里确有这种行，否则本判据只是纸面规则
    expect(
      cmds.filter((c) => /^\s*#/.test(c.text) && /scripts\/backup-mongo\.sh/.test(c.text)).length
    ).toBeGreaterThanOrEqual(1);
  });

  test('扫描清单只含说明书：记录域（CHANGELOG / deliverables / adr）不在其中', () => {
    const flat = RUNBOOKS.join('\n');
    expect(flat).not.toMatch(/CHANGELOG|deliverables|docs\/adr/);
    expect(RUNBOOKS).toEqual(expect.arrayContaining(['README.md', 'docs/incident-response.md']));
  });

  test('续行合并与 CRLF：跨行的一条命令不会被当成两条/漏检', () => {
    const doc = [
      '```bash',
      'MONGODB_URI_FILE=./secrets/mongodb_uri \\',
      '  HMAC_SECRET_FILE=./secrets/hmac_secret \\',
      '  node scripts/verify-audit-chain.js',
      '```',
    ].join('\r\n');
    const cmds2 = collectCommands('synthetic.md', doc);
    expect(cmds2).toHaveLength(1);
    expect(violations(cmds2[0])).toEqual([]);
    // 若去掉第一行的前缀，合并后的那一行必须仍被 URI 通道点亮
    const broken = cmds2[0].text.replace('MONGODB_URI_FILE=./secrets/mongodb_uri ', '');
    expect(violations({ text: broken }).join('\n')).toMatch(/缺 MONGODB_URI/);
  });
});
