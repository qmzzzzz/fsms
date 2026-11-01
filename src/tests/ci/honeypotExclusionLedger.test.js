/**
 * 蜜罐账户「枚举面排除」台账闸（P0 地基，与 P1 登录诱饵接线同批落地）
 *
 * 【它防的是哪一种漂移】蜜罐账户必须在**所有面向人的用户枚举面**上不存在：用户列表、
 * 用户计数、按角色的成员清单/计数、统计聚合、部门成员集、以及哨兵遮蔽对账。
 * 排除判据只有一份（constants/honeypotAccounts.js 的 HONEYPOT_EXCLUDED_FILTER /
 * withHoneypotExcluded），但**消费点会随业务增长而增加**：
 * 新写一个 `User.find(...)`/`countDocuments`/`aggregate` 的人不会收到任何提示，
 * 于是蜜罐账户悄悄出现在某个新清单里 —— 攻击者（或任何一个持 user:read 的管理员）
 * 看到一个零角色账户挂在列表里，蜜罐当场失效。
 *
 * 【判据】扫描 src/scripts/migrations 里的多文档 User 查询站点（find / countDocuments /
 * aggregate / distinct），每个站点必须落在两类之一：
 *   ① 站点文本里带排除判据（HONEYPOT_EXCLUDED_FILTER 或 withHoneypotExcluded）；
 *   ② 逐条登记在下面的 REGISTERED_NON_MARKER 台账里，且**写明为什么可以不排除**。
 * 双向：登记项的出处文本必须仍在源码里，且必须真的还能匹配到站点（烂成僵尸账即红）。
 *
 * 【为什么有几条是「有意不排除」】删除/匿名化/超管对账这几条**必须**看得见蜜罐账户：
 * 一个被误授超管的蜜罐账户若不进对账集，越权就永远留在库里；管理员删号也要能覆盖它。
 * 台账把这类「反方向」的理由写在同一处，免得下一个人以为漏了而顺手补上排除。
 *
 * 【口径】一切文本判定跑在 helpers/jsCodeOnly 的「只剩代码」视图上：注释里补一个排除串
 * 不能冒充接线，注释里写反例也不会把真代码判成违规。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const User = require('../../models/User');

const ROOT = path.join(__dirname, '../../..');
const DIRS = ['src', 'scripts', 'migrations'];
const SCAN_RE = /\bUser\.(find|countDocuments|aggregate|distinct)\(/g;
const MARKER_RE = /HONEYPOT_EXCLUDED_FILTER|withHoneypotExcluded/;
const EXCLUSION_LITERAL_RE = /isHoneypot:\s*\{\s*\$ne:\s*true\s*\}/g;

/** 收集生产源码（排除测试与 node_modules） */
function collect(dir, acc = []) {
  let entries;
  try {
    entries = fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const entry of entries) {
    if (entry.name === 'node_modules' || entry.name === 'tests' || entry.name === '.git') continue;
    const rel = dir + '/' + entry.name;
    if (entry.isDirectory()) collect(rel, acc);
    else if (entry.name.endsWith('.js')) acc.push(rel);
  }
  return acc;
}

const PROD_FILES = DIRS.flatMap((dir) => collect(dir));
const CODE_BY_FILE = new Map(
  PROD_FILES.map((rel) => [rel, jsCodeOnly(fs.readFileSync(path.join(ROOT, rel), 'utf8'))])
);

/** 括配对切出调用实参（跳过字符串/模板串里的括号） */
function callText(code, openIdx) {
  let depth = 0;
  let quote = null;
  for (let i = openIdx; i < code.length; i += 1) {
    const ch = code[i];
    if (quote) {
      if (ch === '\\') i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch;
    else if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return code.slice(openIdx, i + 1);
    }
  }
  return code.slice(openIdx, openIdx + 200);
}

/** 站点：从所在行行首切到调用收尾，再归一空白（便于写「可在源码里逐字找到」的出处） */
function scanSites() {
  const sites = [];
  for (const [rel, code] of CODE_BY_FILE) {
    SCAN_RE.lastIndex = 0;
    let match;
    while ((match = SCAN_RE.exec(code)) !== null) {
      const openIdx = match.index + match[0].length - 1;
      const lineStart = code.lastIndexOf('\n', match.index) + 1;
      const stmt = (code.slice(lineStart, openIdx) + callText(code, openIdx))
        .replace(/\s+/g, ' ')
        .trim();
      sites.push({ file: rel, op: match[1], stmt, marked: MARKER_RE.test(stmt) });
    }
  }
  return sites;
}

const norm = (text) => text.replace(/\s+/g, ' ').trim();

/** 必须带排除判据的接线点（判据存在性的正面清单） */
const MUST_CARRY_MARKER = [
  { file: 'src/services/userService.js', anchor: 'const query = { ...HONEYPOT_EXCLUDED_FILTER };' },
  {
    file: 'src/services/userService.js',
    anchor: '[{ $match: HONEYPOT_EXCLUDED_FILTER }, ...pipeline]',
  },
  {
    file: 'src/services/roleService.js',
    anchor: 'withHoneypotExcluded({ roles: { $in: roleIds } })',
  },
  { file: 'src/services/roleService.js', anchor: 'withHoneypotExcluded({ roles: role._id })' },
  {
    file: 'src/services/roleService.js',
    anchor: 'User.find(withHoneypotExcluded({ roles: roleId }))',
  },
  {
    file: 'src/services/roleService.js',
    anchor: 'User.countDocuments(withHoneypotExcluded({ roles: roleId }))',
  },
  {
    file: 'src/services/auditScopeFilter.js',
    anchor: "User.distinct('_id', withHoneypotExcluded({ department }))",
  },
  {
    file: 'src/services/canaryWatch.js',
    anchor: 'User.find(withHoneypotExcluded({ username: { $in: names } }))',
  },
];

/** 不带排除判据的站点：逐条登记出处 + 理由（双向核对） */
const REGISTERED_NON_MARKER = [
  {
    file: 'src/services/userService.js',
    anchor: 'withListBudget(User.find(query)',
    why: 'query 由 buildListQuery 构造，排除判据在那里的单个 const（本文件 MUST_CARRY_MARKER 第 1 条盯着它）',
  },
  {
    file: 'src/services/userService.js',
    anchor: 'User.countDocuments(query, listCountOptions())',
    why: '与上一条共用同一个 query 对象（列表与计数同源，必须同口径）',
  },
  {
    file: 'src/services/userService.js',
    anchor: 'return User.find({ _id: { $in: ids } })',
    why: '按 _id 收敛的批量载入（findBatchUsers / findUserSnapshots 同形态），只能命中已知 id',
  },
  {
    file: 'src/services/userService.js',
    anchor: 'User.find({ _id: { $in: list } })',
    why: '按 _id 收敛（范围判定用的两列投影）',
  },
  {
    file: 'src/services/userService.js',
    anchor: "const affected = await User.find(filter, '_id')",
    why: '**有意不排除**：管理员批量删号前置取 id，filter 由控制器收敛；排除即等于「管理员删不掉这个账户」',
  },
  {
    file: 'src/services/userAnonymizationBatch.js',
    anchor: "User.find(filter, '_id')",
    why: '**有意不排除**：批量匿名化与批量删除同一口径（删除权请求必须能覆盖任何账户）',
  },
  {
    file: 'src/services/initData/adminAccount.js',
    anchor: 'roles: superRole._id,',
    why: '**有意不排除**：超管角色对账必须看得见被误授超管的账户（蜜罐在内），否则越权会永久留在库里',
  },
  {
    file: 'src/services/InspectionService.js',
    anchor: "User.find({ _id: { $in: ids }, status: 'active' })",
    why: '按 id 收敛的处理人存在性校验（id 来自管理员提交的指派对象）',
  },
  {
    file: 'src/services/userPermissionService.js',
    anchor: 'User.find({ _id: { $in: missing } })',
    why: '按 id 收敛的权限缓存回填（missing 由缓存 miss 集合派生）',
  },
  {
    file: 'src/services/honeypotWatch.js',
    anchor: 'const taken = (await User.find({ isHoneypot: true })',
    why: '**有意不排除**：这条查询的对象**就是**蜜罐账户本身（取已有诱饵的 realName 供画像去重），排除它等于把去重集清空、允许两份同名画像',
  },
  {
    file: 'src/services/honeypotWatch.js',
    anchor: 'const mfaOnDecoy = await User.countDocuments({ isHoneypot: true, mfaEnabled: true })',
    why: '**有意不排除**：这条查询的对象**就是**蜜罐账户本身（统计开了 MFA 的诱饵数），排除它等于把判据自身清空',
  },
  {
    file: 'src/services/websocketService/lifecycle.js',
    anchor: 'User.find({ _id: { $in: uniqueUserIds } })',
    why: '按 id 收敛的批量状态读取（在线连接携带的 userId）',
  },
];

const classify = (stmt) => {
  if (MARKER_RE.test(stmt)) return 'marked';
  return REGISTERED_NON_MARKER.some((entry) => stmt.includes(norm(entry.anchor)))
    ? 'registered'
    : 'unregistered';
};

const SITES = scanSites();
const markedSites = SITES.filter((site) => site.marked);
const unmarkedSites = SITES.filter((site) => !site.marked);

describe('蜜罐账户枚举面排除台账（新增枚举点必须显式表态）', () => {
  test('前提自证：扫描集非空、判据非空转、且判据自带正反样本', () => {
    expect(PROD_FILES.length).toBeGreaterThanOrEqual(150);
    expect(SITES.length).toBeGreaterThanOrEqual(15);
    expect(markedSites.length).toBeGreaterThanOrEqual(6);
    expect(unmarkedSites.length).toBeGreaterThanOrEqual(8);
    expect(classify('const q = await User.find(withHoneypotExcluded({}))')).toBe('marked');
    expect(classify('const q = await User.find({ status: "active" })')).toBe('unregistered');
    expect(classify('await ' + REGISTERED_NON_MARKER[2].anchor)).toBe('registered');
  });

  test('正面清单：每一处必须带排除判据的接线都真的带上了', () => {
    for (const entry of MUST_CARRY_MARKER) {
      const code = CODE_BY_FILE.get(entry.file);
      expect({
        file: entry.file,
        anchor: entry.anchor,
        present: Boolean(code && code.includes(norm(entry.anchor))),
      }).toEqual({
        file: entry.file,
        anchor: entry.anchor,
        present: true,
      });
    }
  });

  test('排除判据只有一份声明：$ne true 的字面量在整仓生产代码里恰好出现一次', () => {
    const owners = PROD_FILES.filter((rel) => {
      const hits = CODE_BY_FILE.get(rel).match(EXCLUSION_LITERAL_RE);
      return hits !== null;
    });
    expect(owners).toEqual(['src/constants/honeypotAccounts.js']);
  });

  test('反向清单：每个站点要么带判据、要么登记在案（新增站点必须表态，否则红）', () => {
    const unregistered = SITES.filter((site) => classify(site.stmt) === 'unregistered').map(
      (site) => site.file + ' :: ' + site.stmt
    );
    expect(unregistered).toEqual([]);
  });

  test('双向：登记项的出处必须仍在源码里，且必须真的还能匹配到站点（禁止僵尸账）', () => {
    const seen = new Set();
    for (const entry of REGISTERED_NON_MARKER) {
      const code = CODE_BY_FILE.get(entry.file);
      expect({
        file: entry.file,
        why: entry.why.length > 8,
        present: Boolean(code && code.includes(norm(entry.anchor))),
      }).toEqual({
        file: entry.file,
        why: true,
        present: true,
      });
      const key = entry.file + ' :: ' + norm(entry.anchor);
      expect(seen.has(key)).toBe(false);
      seen.add(key);
      const matched = SITES.filter(
        (site) => site.file === entry.file && site.stmt.includes(norm(entry.anchor))
      );
      expect(matched.length).toBeGreaterThanOrEqual(1);
    }
    // 每个不带判据的站点都必须被台账覆盖，否则它会在上一条用例里已经报红——这里兜一层
    for (const site of unmarkedSites) {
      const covering = REGISTERED_NON_MARKER.filter(
        (entry) => entry.file === site.file && site.stmt.includes(norm(entry.anchor))
      );
      expect(covering.length).toBeGreaterThanOrEqual(1);
    }
  });

  test('模型侧：标志字段存在、默认 false、且默认不出现在用户读响应里', () => {
    const path_ = User.schema.path('isHoneypot');
    expect(Boolean(path_)).toBe(true);
    expect(path_.instance).toBe('Boolean');
    expect(path_.defaultValue).toBe(false);
    expect(User.RESPONSE_EXCLUDE.split(' ')).toContain('-isHoneypot');
    expect(User.RESPONSE_EXCLUDE_PII_VISIBLE.split(' ')).toContain('-isHoneypot');
  });
});
