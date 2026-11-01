/**
 * 「只有 authenticate、没有权限中间件」的端点台账（P1c）
 *
 * 为什么要有这本台账：蜜罐的核心是一个接线点——`middleware/auth.js` 里那句 `steer(...)`
 * 把诱饵会话的请求从真实控制器前改道。于是"哪些端点**没有**权限码可挡"这件事，
 * 就直接决定了诱饵会话能摸到多少真实处理器：只要 `authenticate` 通过而路由上又没有
 * `checkPermission`，请求就会**落到真实控制器里**（自服务写操作甚至会产生真实副作用）。
 * 本批靠单点改道让这些端点对攻击者无关紧要，但"无关紧要"必须是一条可核对的清单，
 * 而不是一句口头承诺——所以逐条登记「陷阱会话在这里看到什么」。
 *
 * 与既有两条契约门禁的分工（不是重复）：
 *   · readPermissionContract.test.js / writePermissionContract.test.js 管"没有权限闸是否安全"
 *     （白名单 + 理由 + 白名单不许失效）；
 *   · 本台账管"被改道之后回什么"：每条只读/自服务端点在陷阱会话里的**实际形态**，
 *     并由 resolveFileResponse / resolveSelfResponse / resolveDecoyVerdict 现算一遍与声明比对（声明漂了就红）。
 *
 * 三条判据：
 *   ① 扫描面 = src/routes/*.js 与 src/app.js 的**全部动词**声明（读侧契约只扫 GET，
 *      而自服务写端点恰恰是"只有 authenticate"的大头）；
 *   ② 声明与实况双向一致：多一条（路由改名/新增没登记）、少一条（登记了但路由没了）都红；
 *   ③ 每个条目都必须到手一个**确定的**形态，且**永不允许**落在 PASSTHROUGH 上——
 *      放行等于把真实处理器接到陷阱会话上（迁移臂/白名单若把它当自助端点放行，本闸先红）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const ROUTES_DIR = path.join(ROOT, 'src/routes');
const APP_SRC = fs.readFileSync(path.join(ROOT, 'src/app.js'), 'utf8');
const {
  HONEYPOT_VERDICT,
  resolveDecoyPayload,
  resolveDecoyVerdict,
} = require('../../constants/honeypotDecoy');
const { resolveFileResponse } = require('../../services/honeypotDecoyFiles');
const { resolveSelfResponse } = require('../../services/honeypotDecoySelf');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');

/** app.js 的挂载表：router 变量名 → 挂载前缀（台账要把路由路径拼成真实请求路径才能现算形态） */
const MOUNT_RE = /app\.use\('(\/api\/[a-z-]+)',\s*([A-Za-z0-9_]+)\)/g;
const MOUNT_OF = new Map([...APP_SRC.matchAll(MOUNT_RE)].map((m) => [m[2], m[1]]));

const ANY_DECL_RE = /(?<![\w.])(?:app|router)\.(?:get|post|put|delete|patch|all)\s*\(/g;
const HEAD_RE = /^(?:app|router)\.(get|post|put|delete|patch|all)\s*\(/;

/** 块尾：下一条任意动词声明、顶层块收尾 `\n}`、文件末尾，取最早者（与读侧契约同法） */
const blockEndOf = (source, start) => {
  ANY_DECL_RE.lastIndex = start + 1;
  const next = ANY_DECL_RE.exec(source);
  let end = next ? next.index : source.length;
  const topClose = source.indexOf('\n}', start + 1);
  if (topClose !== -1 && topClose < end) end = topClose;
  return end;
};

/** 抽出所有动词声明的块；method 取声明首行动词 */
const extractBlocks = (source) => {
  const decls = [];
  let match;
  ANY_DECL_RE.lastIndex = 0;
  while ((match = ANY_DECL_RE.exec(source)) !== null) decls.push(match.index);
  const blocks = [];
  for (const idx of decls) {
    const head = HEAD_RE.exec(source.slice(idx, idx + 40));
    if (!head) continue;
    const raw = source.slice(idx, blockEndOf(source, idx));
    const route = (raw.match(/['"`](\/[^'"`]*)/) || [null, '(未解析路径)'])[1];
    const code = jsCodeOnly(raw); // 注释视图走单点实现（tests/helpers/jsCodeOnly）：私有复制品会被 commentViewSingleSource 判红
    if (!/\bauthenticate\b/.test(code)) continue; // 只看已鉴权块
    if (/checkPermission\s*\(|checkViewSensitivePermission/.test(code)) continue; // 有权限码的不归本台账
    blocks.push({ method: head[1].toUpperCase(), route, code });
  }
  return blocks;
};

/** 扫描一组（文件名 → 源码），返回台账键与规模（键形如 `authRoutes.js GET /me`） */
const scan = (sources) => {
  const keys = [];
  let scannedFiles = 0;
  for (const [file, source] of Object.entries(sources)) {
    const blocks = extractBlocks(source);
    if (blocks.length > 0) scannedFiles += 1;
    for (const block of blocks) keys.push(file + ' ' + block.method + ' ' + block.route);
  }
  return { keys, scannedFiles };
};

/**
 * 陷阱会话在该端点上的实际形态（**现算**，不看本文件的声明）
 *
 * deny403      通用改道判为拒绝：与真实 403 同一个响应构造器，错误体逐字相同
 * decoy-self:<id>  P2 的本人自助面：按会话身份回同形合成体（端点表在 services/honeypotDecoySelf.js）
 * decoy-summary /api/security 其余路径的合成汇总（P1 的形态）
 * avatar404     文件类支路：头像一律"尚未设置头像"的 404
 *
 * 判序必须与 services/honeypotDecoy.js 的 steer 同序（放行 ⇒ 文件类 ⇒ 本人自助面 ⇒ 通用改道），
 * 否则"现算"算的是另一条链——那正是这本台账要防的漂移。
 */
const handlingOf = (key) => {
  const [file, method, route] = key.split(' ');
  const fullPath = MOUNT_OF.get(file.replace(/\.js$/, '')) + route;
  const verdict = resolveDecoyVerdict({ method, path: fullPath });
  if (verdict === HONEYPOT_VERDICT.PASSTHROUGH) return 'passthrough';
  const fileResponse = resolveFileResponse({ method, path: fullPath, query: {} });
  if (fileResponse) {
    return fileResponse.code === 'AVATAR_NOT_FOUND' ? 'avatar404' : 'file-refusal';
  }
  const selfResponse = resolveSelfResponse({ method, path: fullPath, query: {}, session: {} });
  if (selfResponse) return 'decoy-self:' + selfResponse.endpoint;
  if (verdict !== HONEYPOT_VERDICT.DECOY) return 'deny403';
  const payload = resolveDecoyPayload({ path: fullPath });
  return payload && payload.kind === 'summary'
    ? 'decoy-summary'
    : 'decoy-' + (payload ? payload.kind : 'none');
};

/**
 * 台账：21 条（2026-10-31 实测；读侧七条在 P2 落地"本人自助面"后从 read-shape 转为 none）
 *
 * gap 的取值固定三种，含义是"陷阱的回答与真实会话差在哪"——
 *   none         形态与真实同一种：读侧七条回的是同字段的合成体（内容为合成身份，不是库里的真行）
 *   read-shape   真实链按 req.user 回 200 本人数据，陷阱回 403 或合成汇总（本批已清零，取值保留）
 *   write-locked 真实链对本人可成功写，陷阱一律 403（有意封锁：诱饵不产生真实副作用）
 * realWould 是"真实会话在这里会拿到什么"，写给后来者判断 gap 用。
 */
const LEDGER = {
  'authRoutes.js GET /me': {
    handling: 'decoy-self:me',
    gap: 'none',
    realWould: '200 本人资料 + 权限清单',
    why: 'P2 本人自助面：按会话身份回同形合成体（email 用呈现层域名、角色/权限取合成目录），不读真实集合',
  },
  'authRoutes.js GET /mfa/status': {
    handling: 'decoy-self:mfa-status',
    gap: 'none',
    realWould: '200 { enabled, recoveryCodesRemaining }',
    why: '同上：恒回 { enabled:false, recoveryCodesRemaining:0 }——诱饵账户不得开 MFA，故这一形态本身就是真的',
  },
  'authRoutes.js GET /sessions': {
    handling: 'decoy-self:sessions',
    gap: 'none',
    realWould: '200 本人活跃会话列表',
    why: '同上：只呈现当前这一条（sid 取自会话上下文），无 sid 时按真实口径回空表',
  },
  'securityRoutes.js GET /my-info': {
    handling: 'decoy-self:my-info',
    gap: 'none',
    realWould: '200 本人安全设置（脱敏后）',
    why: 'P2：与 account.js 同字段、同判据（邮箱/手机各脱敏一次、评分与建议同式），内容取自合成轨迹',
  },
  'securityRoutes.js GET /bindings': {
    handling: 'decoy-self:bindings',
    gap: 'none',
    realWould: '200 本人邮箱/手机绑定',
    why: 'P2：三条绑定的值来自呈现层身份（脱敏各一次），不读真实绑定记录',
  },
  'securityRoutes.js GET /my-logs': {
    handling: 'decoy-self:my-logs',
    gap: 'none',
    realWould: '200 本人操作日志',
    why: 'P2：合成轨迹行（_id 形态同 ObjectId、按 days/limit/category 过滤），绝不读真实审计日志——攻击者看不到自己留下的痕迹',
  },
  'securityRoutes.js GET /report-targets': {
    handling: 'decoy-self:report-targets',
    gap: 'none',
    realWould: '200 举报对象候选集（按数据范围收敛）',
    why: 'P2：候选来自合成表 + 会话本人一行，条目 id 用 24 位十六进制（不出现 hp- 前缀），不透露真实记录',
  },
  'authRoutes.js PUT /password': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200（校验旧口令后改密）',
    why: '本人改密：真实链凭旧口令即可成功；陷阱不给任何真实写入口，一律 403',
  },
  'authRoutes.js PUT /profile': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200（改名/电话/部门）',
    why: '本人资料写：同上——有意的写侧封锁（ADR-013 边界表）',
  },
  'authRoutes.js PUT /avatar': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200（写入本人头像字节）',
    why: '本人头像上传：会写真实存储，陷阱恒拒',
  },
  'authRoutes.js DELETE /avatar': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200（删除本人头像）',
    why: '本人头像删除：同上，恒拒',
  },
  'authRoutes.js POST /mfa/enroll': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200/403 REAUTH_REQUIRED（需当前口令二次验证）',
    why: '本人 MFA 注册：真实链在二次验证通过后成功；陷阱恒拒（诱饵不产生任何真实密钥）',
  },
  'authRoutes.js POST /mfa/enable': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200/403 REAUTH_REQUIRED（需口令 + 动态码）',
    why: '本人 MFA 启用：改变安全状态的一步，陷阱恒拒',
  },
  'authRoutes.js POST /mfa/disable': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200/400（需动态码或口令二次验证）',
    why: '本人 MFA 停用：陷阱恒拒',
  },
  'authRoutes.js POST /mfa/recovery-codes': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200/400（需当前动态码）',
    why: '本人恢复码重生成：真链会作废旧码，陷阱恒拒',
  },
  'authRoutes.js DELETE /sessions/others': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200（吊销本人其他会话）',
    why: '本人会话吊销：陷阱恒拒（不替攻击者做"清理痕迹"这件事，也不动真实会话表）',
  },
  'authRoutes.js DELETE /sessions/:sid': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200/404（服务层校验归属后吊销）',
    why: '本人指定会话吊销：陷阱恒拒',
  },
  'securityRoutes.js PUT /change-password': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200（校验旧口令后改密）',
    why: '安全中心的改密：与 authRoutes 的 PUT /password 同一条自服务写，恒拒',
  },
  'securityRoutes.js POST /reauth': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200（凭据校验通过后签发二次验证票据）',
    why: '二次验证票据签发：签发真票据等于给攻击者提权凭据，恒拒',
  },
  'securityRoutes.js POST /report': {
    handling: 'deny403',
    gap: 'write-locked',
    realWould: '200（会写入一条真实举报记录）',
    why: '举报提交：真链会落库，陷阱恒拒——诱饵不许产生任何真实写副作用',
  },
  'avatarRoutes.js GET /:userId': {
    handling: 'avatar404',
    gap: 'none',
    realWould: '404 未设置头像（本人未设头像时）',
    why: '文件类支路：GET/HEAD 一律 404「尚未设置头像」，与真实未设头像同形；不产出任何真实字节',
  },
};

/** 缺口分类必须逐类钉死：P2 里补掉一条就该把这条从清单里划掉（少一条/多一条都红） */
const SELF_READ_KEYS = [
  'authRoutes.js GET /me',
  'authRoutes.js GET /mfa/status',
  'authRoutes.js GET /sessions',
  'securityRoutes.js GET /bindings',
  'securityRoutes.js GET /my-info',
  'securityRoutes.js GET /my-logs',
  'securityRoutes.js GET /report-targets',
];
/** P2（2026-10-31）已把读侧七条接进本人自助面：本清单清零——新增读侧端点仍须先登记再接线 */
const READ_SHAPE_BACKLOG = [];
const WRITE_LOCKED = [
  'authRoutes.js DELETE /avatar',
  'authRoutes.js DELETE /sessions/:sid',
  'authRoutes.js DELETE /sessions/others',
  'authRoutes.js POST /mfa/disable',
  'authRoutes.js POST /mfa/enable',
  'authRoutes.js POST /mfa/enroll',
  'authRoutes.js POST /mfa/recovery-codes',
  'authRoutes.js PUT /avatar',
  'authRoutes.js PUT /password',
  'authRoutes.js PUT /profile',
  'securityRoutes.js POST /reauth',
  'securityRoutes.js POST /report',
  'securityRoutes.js PUT /change-password',
];

describe('只有 authenticate 的端点台账（P1c）：陷阱会话在这里看到什么', () => {
  const routeFiles = fs
    .readdirSync(ROUTES_DIR)
    .filter((f) => f.endsWith('.js') && f !== 'index.js')
    .sort();
  const REAL = {
    ...Object.fromEntries(
      routeFiles.map((f) => [f, fs.readFileSync(path.join(ROUTES_DIR, f), 'utf8')])
    ),
    'app.js': APP_SRC,
  };

  test('前提自证：解析器对合成源的分类正确，且注释里的 checkPermission 不作数', () => {
    const synthetic = [
      "router.get('/plain', ctrl.plain);",
      "router.get('/auth', authenticate, ctrl.auth);",
      "router.post('/commented', authenticate, /* checkPermission('a:b') 只在注释里 */ ctrl.c);",
      "router.put('/perm', authenticate, checkPermission('a:b'), ctrl.p);",
      "router.delete(\n  '/multi',\n  authenticate,\n  ctrl.m\n);",
    ].join('\n');
    const keys = extractBlocks(synthetic).map((b) => b.method + ' ' + b.route);
    expect(keys).toEqual(['GET /auth', 'POST /commented', 'DELETE /multi']);
  });

  test('规模地板：两个注册面都被扫到，台账非空且逐条写了理由/真实形态/缺口分类', () => {
    const result = scan(REAL);
    expect(result.scannedFiles).toBeGreaterThanOrEqual(3);
    expect(result.keys.length).toBeGreaterThanOrEqual(20);
    expect(new Set(result.keys).size).toBe(result.keys.length); // 解析器不许把同一条声明数两遍
    const entries = Object.entries(LEDGER);
    expect(entries.length).toBeGreaterThanOrEqual(20);
    for (const [key, entry] of entries) {
      expect({ key, why: entry.why.length > 10 }).toEqual({ key, why: true });
      expect(
        /^(deny403|decoy-self:[a-z-]+|decoy-summary|avatar404|file-refusal)$/.test(entry.handling)
      ).toBe(true);
      expect(['none', 'read-shape', 'write-locked']).toContain(entry.gap);
      expect(typeof entry.realWould === 'string' && entry.realWould.length > 5).toBe(true);
    }
  });

  test('双向：台账与实况逐条对齐（路由改名/新增没登记都红）', () => {
    const found = new Set(scan(REAL).keys);
    const declared = new Set(Object.keys(LEDGER));
    expect([...found].filter((k) => !declared.has(k))).toEqual([]);
    expect([...declared].filter((k) => !found.has(k))).toEqual([]);
  });

  test('形态现算：每条声明都必须与 resolveFileResponse / resolveDecoyVerdict 现算的结果一致', () => {
    const mismatches = Object.keys(LEDGER)
      .map((key) => ({ key, computed: handlingOf(key), declared: LEDGER[key].handling }))
      .filter((row) => row.computed !== row.declared);
    expect(mismatches).toEqual([]);
  });

  test('永不放行：这 21 条一条都不许落在 PASSTHROUGH（放行 = 真实处理器接到陷阱会话上）', () => {
    const passed = Object.keys(LEDGER)
      .map((key) => ({ key, verdict: handlingOf(key) }))
      .filter((row) => row.verdict === 'passthrough')
      .map((row) => row.key);
    expect(passed).toEqual([]);
    expect(handlingOf('authRoutes.js GET /me')).toBe('decoy-self:me'); // 反证：现算函数真的在算（合成键若拼错会走进这条）
  });

  test('缺口分类逐类钉死：读侧形态差异与写侧封锁都是"有意的清单"，改动必须同轮更新', () => {
    const byGap = (gap) =>
      Object.keys(LEDGER)
        .filter((key) => LEDGER[key].gap === gap)
        .sort();
    expect(byGap('read-shape')).toEqual([...READ_SHAPE_BACKLOG].sort());
    expect(byGap('write-locked')).toEqual([...WRITE_LOCKED].sort());
    expect(byGap('none')).toEqual([...SELF_READ_KEYS, 'avatarRoutes.js GET /:userId'].sort());
  });

  test('每条台账都能拼出已挂载的真实路径（防 app.js 挂载表漂移导致现算落空）', () => {
    const problems = [];
    for (const key of Object.keys(LEDGER)) {
      const [file] = key.split(' ');
      if (!MOUNT_OF.has(file.replace(/\.js$/, ''))) problems.push(file + ' 在 app.js 里找不到挂载');
    }
    expect(problems).toEqual([]);
    expect(MOUNT_OF.size).toBeGreaterThanOrEqual(8);
  });
});
