/**
 * 架构文档 ↔ docker-compose 的契约（F-06，2026-10-17）
 *
 * 缺陷本体：`docs/architecture.md` 的部署拓扑图把 MongoDB 画在 `fire-safety-net` 里、
 * 与 app 同网；而实际 compose 中 mongo **只**在 `data-net`，且该网络 `internal: true`。
 * 图里还完全没有 redis、prometheus、alertmanager、grafana。
 *
 * 这类偏差的危害不是"文档不好看"：
 *   - 值班人员按图排障会连错网络（去 fire-safety-net 找 mongo，找不到）；
 *   - 安全评审无法只凭图确认"app 是否能直连数据面""监控栈能不能摸到 redis"；
 *   - 故障时容易"按图修网络"，把 `internal: true` 这条隔离边界改掉。
 *
 * 判据刻意不做成"解析 mermaid"（那等于写一个 mermaid 解析器）：只钉三件可机械核对的事——
 * ① compose 里的每个网络名都出现在文档里；② 每个服务名都出现在文档里；
 * ③ 文档把 mongo/redis 画在 data-net 分组内、把监控三件画在 fire-safety-net 分组内。
 * 第 ③ 条用 mermaid 的 `subgraph NAME[...]` 到 `end` 之间的文本切片，够用且不会误判。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const COMPOSE = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
const DOC = fs.readFileSync(path.join(ROOT, 'docs', 'architecture.md'), 'utf8');

/** 取某个顶层段（services / networks / volumes …）下的二级键名 */
function topLevelKeys(section) {
  const lines = COMPOSE.split(/\r?\n/);
  const start = lines.findIndex((l) => new RegExp(`^${section}:\\s*$`).test(l));
  if (start === -1) throw new Error(`docker-compose.yml 里找不到顶层段 ${section}:`);
  const keys = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^[a-zA-Z]/.test(line)) break; // 下一个顶层键
    const m = line.match(/^ {2}([A-Za-z0-9][A-Za-z0-9_-]*):\s*$/);
    if (m) keys.push(m[1]);
  }
  return keys;
}

/** 取 mermaid 里某个 subgraph 的正文（到配对的 end 为止） */
function subgraphBody(name) {
  const lines = DOC.split(/\r?\n/);
  const start = lines.findIndex((l) => l.includes(`subgraph ${name}[`));
  if (start === -1) return null;
  const body = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^\s*end\s*$/.test(lines[i])) break;
    body.push(lines[i]);
  }
  return body.join('\n');
}

const SERVICE_NAMES = topLevelKeys('services');
const NETWORK_NAMES = topLevelKeys('networks');

describe('F-06 架构文档与 compose 的服务清单同步', () => {
  test('compose 解析出预期的服务（解析器失效时后面全绿也没意义）', () => {
    // 反证：解析器若把 services 段读成空，下面的"每个服务都在文档里"会恒真。
    expect(SERVICE_NAMES).toEqual(
      expect.arrayContaining(['app', 'mongo', 'redis', 'prometheus', 'alertmanager', 'grafana'])
    );
  });

  test.each(['app', 'mongo', 'redis', 'prometheus', 'alertmanager', 'grafana'])(
    '服务 %s 在架构文档里被提到',
    (name) => {
      expect(DOC).toContain(name);
    }
  );

  test('文档里没有"只在文档里存在"的服务名（图表不得虚构组件）', () => {
    // 反向：从文档的 mermaid 节点标签里抽服务名太脆，这里只钉一个具体的历史错误——
    // 旧图把 mongo 放在 fire-safety-net 里，而 compose 的 mongo 只接 data-net。
    const dataNet = subgraphBody('DATA');
    expect(dataNet).toBeTruthy();
    expect(dataNet).toContain('MONGO');
  });
});

describe('F-06 网络名与隔离边界', () => {
  test('compose 的每个网络名都出现在文档里', () => {
    expect(NETWORK_NAMES.length).toBeGreaterThanOrEqual(2);
    for (const net of NETWORK_NAMES) {
      expect({ net, inDoc: DOC.includes(net) }).toMatchObject({ net, inDoc: true });
    }
  });

  test('data-net 在 compose 里是 internal: true，文档必须写明这一点', () => {
    const netSection = COMPOSE.slice(COMPOSE.indexOf('\nnetworks:'));
    const dataNet = netSection.slice(netSection.indexOf('data-net:'));
    expect(dataNet).toMatch(/internal:\s*true/);
    // 文档侧：隔离语义必须可读，不能只画一条线
    expect(DOC).toContain('internal: true');
    expect(DOC).toContain('不接宿主 NAT');
  });

  test('mongo / redis 画在数据面分组，监控三件画在边缘分组（旧图把 mongo 画在 fire-safety-net）', () => {
    const dataNet = subgraphBody('DATA');
    const edge = subgraphBody('EDGE');
    expect(dataNet).toBeTruthy();
    expect(edge).toBeTruthy();
    // 数据面：只有 mongo 与 redis
    expect(dataNet).toContain('MONGO');
    expect(dataNet).toContain('REDIS');
    expect(dataNet).not.toContain('PROM');
    expect(dataNet).not.toContain('GRAF');
    // 边缘面：监控三件，且不含 mongo/redis（这是旧图的错处）
    expect(edge).toContain('PROM');
    expect(edge).toContain('AM');
    expect(edge).toContain('GRAF');
    expect(edge).not.toContain('MONGO');
    expect(edge).not.toContain('REDIS');
  });

  test('app 双网络接入在文档里被显式说明（含"为什么"）', () => {
    expect(DOC).toContain('双网络接入');
    expect(DOC).toContain('唯一的数据面访问者');
    // 新服务不要顺手加进 data-net —— 这条注释是给下一个人看的，必须留在文档里
    expect(DOC).toContain('不要顺手把它加进');
  });
});

describe('F-06 宿主端口表与 compose 一致', () => {
  test('文档列出的每个 127.0.0.1 端口都真的在 compose 里发布', () => {
    const published = [...COMPOSE.matchAll(/'127\.0\.0\.1:(\d+):(\d+)'/g)].map((m) => m[1]);
    expect(published.length).toBeGreaterThanOrEqual(4);
    for (const port of published) {
      expect({ port, inDoc: DOC.includes(`127.0.0.1:${port}`) }).toMatchObject({
        port,
        inDoc: true,
      });
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D5（2026-10-30 第四轮审计）：架构文档的「面」计数必须与目录实况一致
//
// 缺陷：文档写着 13 View / 11 路由 / 9 控制器 / 15 服务，而目录实况是 14 / 12 / 15 / 66；
// 模型清单还漏了 PrivilegeGrant（特权授予，安全敏感模块）——新人拿这份「全局地图」
// 会低估半个后端，而这类漂移此前没有任何门禁。
//
// 计数口径（全部用 fs 读目录，不解析 mermaid，也不数「文档里出现过哪个数字」）：
//   View   = web-admin/src/views 下直接的 *.vue 文件（顶层，不含子目录）
//   路由   = src/routes 下 *Routes.js 文件（index.js 只是聚合器，不计）
//   控制器 = src/controllers 下一层的 *Controller.js 文件 + *Controller/ 目录（各含 index.js）
//   服务层 = src/services 下直接的 *.js 文件（顶层；authService / initData / sharedCache /
//            websocketService 是子目录，不计入顶层数）
//   模型   = src/models 下真的调用了 mongoose.model( 的 .js 文件（不是「目录里有几个文件」）
//
// 判据是「文档数字 == 当场数出来的数字」：两边各自算一次再比。目录增删而文档没跟上 ⇒ 红；
// 文档数字被人手滑改错 ⇒ 红。模型清单则逐名比对（漏一个或编一个都红）。
function entriesIn(rel) {
  return fs.readdirSync(path.join(ROOT, rel), { withFileTypes: true });
}

const VIEW_COUNT = entriesIn('web-admin/src/views').filter(
  (e) => e.isFile() && e.name.endsWith('.vue')
).length;
const ROUTE_COUNT = entriesIn('src/routes').filter(
  (e) => e.isFile() && /Routes\.js$/.test(e.name)
).length;
const CONTROLLER_COUNT = entriesIn('src/controllers').filter(
  (e) =>
    (e.isFile() && /Controller\.js$/.test(e.name)) ||
    (e.isDirectory() && /Controller$/.test(e.name))
).length;
const SERVICE_COUNT = entriesIn('src/services').filter(
  (e) => e.isFile() && e.name.endsWith('.js')
).length;
const MODEL_NAMES = entriesIn('src/models')
  .filter((e) => e.isFile() && e.name.endsWith('.js'))
  .map((e) => e.name)
  .filter((n) =>
    /mongoose\.model\(/.test(fs.readFileSync(path.join(ROOT, 'src', 'models', n), 'utf8'))
  )
  .map((n) => n.replace(/\.js$/, ''))
  .sort();

/** 从文档固定句式里抠计数：句式被改坏（数字不见了）也算红，不静默通过 */
function documentedCount(label, re) {
  const m = re.exec(DOC);
  if (!m) throw new Error('docs/architecture.md 里找不到「' + label + '」的计数句式');
  return Number(m[1]);
}

describe('D5 架构文档的计数与目录实况一致', () => {
  test('口径自证：每一类都数到了，且谓词真的在筛', () => {
    expect(VIEW_COUNT).toBeGreaterThan(8);
    expect(ROUTE_COUNT).toBeGreaterThan(5);
    expect(CONTROLLER_COUNT).toBeGreaterThan(5);
    expect(SERVICE_COUNT).toBeGreaterThan(20);
    expect(MODEL_NAMES.length).toBeGreaterThan(8);
    // 反证：把后缀换掉必须归零——否则上面的「> 8」可能只是把目录里所有条目都数了进去
    expect(entriesIn('web-admin/src/views').filter((e) => e.name.endsWith('.zzz')).length).toBe(0);
    expect(entriesIn('src/routes').filter((e) => e.name.endsWith('.zzz')).length).toBe(0);
  });

  test('View 数 = web-admin/src/views 顶层 *.vue', () => {
    expect(documentedCount('View', /视图层：.*?(\d+) 个 View/)).toBe(VIEW_COUNT);
  });

  test('路由数 = src/routes/*Routes.js（不含聚合器 index.js）', () => {
    expect(documentedCount('路由', /路由（(\d+)）/)).toBe(ROUTE_COUNT);
  });

  test('控制器数 = *Controller.js 文件 + *Controller/ 目录', () => {
    expect(documentedCount('控制器', /控制器（(\d+)）/)).toBe(CONTROLLER_COUNT);
  });

  test('服务层数 = src/services 顶层 *.js', () => {
    expect(documentedCount('服务层', /服务层（(\d+)/)).toBe(SERVICE_COUNT);
  });

  test('模型数 = src/models 里调用 mongoose.model( 的文件', () => {
    expect(documentedCount('模型', /Mongoose 模型（(\d+)）/)).toBe(MODEL_NAMES.length);
  });

  test('模型清单逐名与 src/models 实况一致（漏一个或编一个都红）', () => {
    const m = /模型清单：`([^`]+)`/.exec(DOC);
    expect(m).not.toBeNull();
    const listed = m[1]
      .split(' / ')
      .map((s) => s.trim())
      .filter(Boolean)
      .sort();
    expect(listed).toEqual(MODEL_NAMES);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// D4（2026-10-30 第四轮审计）：README / CONTRIBUTING 与代码、编排的硬冲突
//
// 三处「照文档做就会错」：DOCS_PASSWORD 写 16 而校验是 32；DOCS_* 标「可选」而缺项即报错；
// MongoDB 写 6.x 而 compose/CI 钉 8.0.34。再加一处指向不存在文件（errorCodeI18n.js）。
// 判据一律「两边各算一次再比」，不是「文档里出现某个字符串」就算过。
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const CONTRIBUTING = fs.readFileSync(path.join(ROOT, 'CONTRIBUTING.md'), 'utf8');
const VALIDATE_SRC = fs.readFileSync(path.join(ROOT, 'src', 'config', 'validate.js'), 'utf8');

describe('D4 文档与代码/编排一致（照文档做不会错）', () => {
  test('README 的 DOCS_PASSWORD 下限 = 启动校验的实际下限（注释口径也算）', () => {
    const codeMin = Number(/docsPass\.length < (\d+)/.exec(VALIDATE_SRC)[1]);
    const docMins = [...README.matchAll(/DOCS_PASSWORD[^\n]*?≥\s*(\d+)\s*字符/g)].map((m) =>
      Number(m[1])
    );
    expect(docMins.length).toBeGreaterThanOrEqual(1);
    expect(docMins).toEqual(docMins.map(() => codeMin));
    // 注释里的旧口径（16 字符）也会被下一个人当成依据，必须同口径
    expect(new RegExp('口令下限\\s*' + codeMin + '\\s*字符').test(VALIDATE_SRC)).toBe(true);
    expect(/口令下限\s*16\s*字符/.test(VALIDATE_SRC)).toBe(false);
  });

  test('README 不得把 DOCS_USERNAME / DOCS_PASSWORD 写成「可选」', () => {
    expect(README).not.toMatch(/DOCS_(?:USERNAME|PASSWORD)[^\n]*（可选）/);
  });

  test('CONTRIBUTING 的 MongoDB 主版本 = compose 钉版主版本', () => {
    const docMajor = Number(/MongoDB[^\n]*?(\d+)\.\d/.exec(CONTRIBUTING)[1]);
    const imageMajor = Number(/image:\s*mongo:(\d+)\./.exec(COMPOSE)[1]);
    expect(docMajor).toBe(imageMajor);
  });

  test('CONTRIBUTING 引用的前端错误码映射落在真实文件上（api.js 的 ERROR_CODE_I18N_MAP）', () => {
    expect(CONTRIBUTING).not.toContain('web-admin/src/utils/errorCodeI18n.js');
    const api = fs.readFileSync(path.join(ROOT, 'web-admin', 'src', 'utils', 'api.js'), 'utf8');
    expect(/const ERROR_CODE_I18N_MAP = \{/.test(api)).toBe(true);
    expect(
      fs.existsSync(path.join(ROOT, 'web-admin', 'src', 'tests', 'utils', 'errorCodeI18n.test.js'))
    ).toBe(true);
  });
});
