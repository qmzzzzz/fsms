/**
 * 单进程依赖清单的完整性门禁（P3-19 收口）
 *
 * 为什么需要：`src/constants/runtime.js` 的 SINGLE_PROCESS_DEPENDENCIES 是
 * 「多实例部署时哪些机制会静默失效」的**唯一**事实来源 —— 启动期校验
 * （`assertSingleProcessAssumptions`）与 Redis 降级提示
 * （`sharedCache.degradedMechanismHint`）都直接读它。清单漏项 ⇒ 运维拿到的
 * 失效清单不全 ⇒ 以为没问题的那些地方其实正在出问题。
 *
 * 该清单已经漂移过一轮，且两个方向都错：
 *   - **漏**：`middleware/security.js` 的 IP 封禁缓存、`services/auditScopeFilter.js`
 *     的部门成员缓存、`models/SystemConfig.js` / `models/IPBlacklist.js` 的 TTL 缓存、
 *     `services/userPermissionService.js` 的权限缓存等均未登记 —— 其中多项是
 *     **安全控件**（封禁、数据范围过滤），不是"数字抖动"。
 *   - **假（死引用）**：验证码存储的 module 写作 `utils/captchaStore`，而
 *     **该文件根本不存在**（真实文件是 `services/captchaService.js`）。
 *   - **假（反向）**：文件头注释一度把「MFA 重放计数」列为进程内 Map，而它早已是
 *     `User.mfaLastCounter` + `mfaService.claimTotpWindow` 的 Mongo 原子认领，
 *     跨进程天然一致 —— 登记它会让运维误判重放防护也会失效。
 *
 * 因此钉四条：① 必含集合；② 不得含已外置到 Mongo 的机制；③ 每条 module 路径必须真实存在；
 * ④ 全仓模块级 Map/Set 必须「要么登记、要么进显式豁免表」——
 * 新增进程内状态而两者都没做，本用例变红。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '../../..');
const SRC_DIR = path.join(ROOT, 'src');

const { SINGLE_PROCESS_DEPENDENCIES } = require(path.join(ROOT, 'src/constants/runtime'));

/** 必须登记的进程内状态机制。新增进程内状态时同时补这里，否则下方第 ④ 条会先红。 */
const REQUIRED_MODULES = [
  'utils/auditChain.js',
  'services/auditBuffer.js',
  'middleware/rateLimit.js',
  'middleware/auth.js',
  'services/captchaService.js',
  'services/statsCache.js',
  'services/securityAlert.js',
  'middleware/security.js',
  'services/auditScopeFilter.js',
  'models/SystemConfig.js',
  'models/IPBlacklist.js',
  'services/userPermissionService.js',
  'services/sessionService.js',
  'services/reportDashboardService.js',
  'services/auditMonitor.js',
  'services/websocketService.js',
];

/**
 * 已把状态放进 Mongo、跨进程天然一致的机制，**不得**登记进本清单。
 * 登记它们会让运维在多实例部署时误以为这些防护也会失效，
 * 从而把注意力从真正失效的项上移开（假警报训练忽略真信号）。
 */
const MUST_NOT_INCLUDE = ['mfaService', 'mfaLastCounter', 'UserSession'];

/**
 * 扫到模块级 Map/Set 但**无需登记**的文件 → 理由。
 *
 * 判据：该集合要么是「静态字面量 / 由常量派生的只读集合」，要么「按设计就是每进程一份」
 * （指标注册表由 Prometheus 逐实例抓取），跨进程不一致不构成任何失效。
 * 除此之外的一切模块级可变集合都必须进 SINGLE_PROCESS_DEPENDENCIES。
 */
const EXEMPT_MODULES = {
  'config/validate.js': '静态字面量 Set（环境别名 / 真值词表），只读',
  // SECURITY_RELEVANT，静态字面量 Set（哪些 immutable 档位项该计入安全告警面），只读。
  // 与同族的 config/validate.js、legacyCbcGuard.js 完全同构：是「判据词表」而非进程内状态。
  'config/immutableConfigGuard.js': 'SECURITY_RELEVANT，静态字面量 Set，只读',
  'constants/breachedPasswords.js': '静态弱口令词表，只读数据',
  'middleware/protocolCompliance.js': 'HOST_GATE_EXEMPT_PATHS，静态字面量 Set',
  'middleware/validateObjectId.js':
    '进程内幂等守卫（WeakSet 记录已注册的 Router；Router 是 require 缓存的进程内单例），无跨进程语义',
  'routes/wellKnownRoutes.js': 'CLIENT_ERROR_KINDS，静态字面量 Set',
  'services/behaviorBaseline.js': 'VOLUME_FEATURES / NON_ADDITIVE_FEATURES，静态字面量 Set',
  'services/sharedCache.js': '共享缓存基础设施自身（memStore 是 Redis 未就绪时的回退实现）',
  'utils/auditMeta.js': 'REGISTERED_ACTIONS，由 AUDIT_LOG_ACTIONS 派生的只读集合',
  'utils/metrics.js': 'Prometheus 指标注册表，按设计逐实例各一份',
  'utils/metricsAuditDrops.js': 'Prometheus 指标注册表，按设计逐实例各一份',
  'utils/mongoFailureAttribution.js': '基础设施错误名/码词表，静态字面量 Set',
};

/** 递归收集 src 下全部非测试 .js 文件 */
const collectSourceFiles = (dir, acc = []) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'tests' || entry.name === 'node_modules') continue;
      collectSourceFiles(full, acc);
    } else if (entry.name.endsWith('.js')) {
      acc.push(full);
    }
  }
  return acc;
};

const relOf = (full) => path.relative(SRC_DIR, full).replace(/\\/g, '/');

/** 模块级（缩进 0）声明的可变容器 */
const MODULE_LEVEL_CONTAINER =
  /^(?:const|let|var)\s+[\w$]+\s*=\s*new\s+(?:Map|Set|WeakMap|WeakSet)\b/gm;

const scanModuleLevelContainers = () => {
  const hits = [];
  for (const file of collectSourceFiles(SRC_DIR)) {
    const src = fs.readFileSync(file, 'utf8');
    const matches = src.match(MODULE_LEVEL_CONTAINER);
    if (matches && matches.length > 0) hits.push({ module: relOf(file), count: matches.length });
  }
  return hits;
};

const inventoryModules = () => SINGLE_PROCESS_DEPENDENCIES.map((d) => d.module);

describe('单进程依赖清单完整性（constants/runtime.js）', () => {
  test('① 必含集合：已知的进程内状态机制一项都不能少', () => {
    const modules = inventoryModules();
    const missing = REQUIRED_MODULES.filter((m) => !modules.includes(m));
    expect({ missing }).toEqual({ missing: [] });
  });

  test('② 不得含已外置到 Mongo 的机制（否则是假警报）', () => {
    const joined = inventoryModules().join(',');
    for (const banned of MUST_NOT_INCLUDE) {
      expect(joined).not.toContain(banned);
    }
  });

  test('③ 每条 module 都指向真实存在的文件（死引用会让清单指向不存在的机制）', () => {
    const dead = [];
    for (const d of SINGLE_PROCESS_DEPENDENCIES) {
      const candidates = [
        path.join(SRC_DIR, d.module),
        path.join(SRC_DIR, `${d.module}.js`),
        path.join(SRC_DIR, d.module, 'index.js'),
      ];
      if (!candidates.some((c) => fs.existsSync(c))) dead.push(d.module);
    }
    expect({ dead }).toEqual({ dead: [] });
  });

  test('④ 模块级 Map/Set 全覆盖：要么登记，要么在豁免表里写明理由', () => {
    const modules = inventoryModules();
    const unaccounted = scanModuleLevelContainers()
      .map((h) => h.module)
      .filter((m) => !modules.includes(m) && !(m in EXEMPT_MODULES));
    expect({ unaccounted }).toEqual({ unaccounted: [] });
  });

  test('豁免表不得残留已删除或已登记的文件（否则豁免表自身腐化）', () => {
    const modules = inventoryModules();
    const stale = Object.keys(EXEMPT_MODULES).filter(
      (m) => !fs.existsSync(path.join(SRC_DIR, m)) || modules.includes(m)
    );
    expect({ stale }).toEqual({ stale: [] });
  });

  test('⑤ 走 sharedCache 失效广播的机制必须标 redisExternalized（否则 Redis 就绪时仍被误报）', () => {
    // 反向断言：缓存本体留在进程内、靠 sharedCache 广播失效的机制，
    // 在 Redis 就绪时是**跨实例一致**的，不该继续出现在"将静默降级"清单里。
    // services/statsCache.js 正是漏标这一项 ⇒ 每次启动都对运维说了一句假话。
    // 例外：middleware/rateLimit.js 通过 rate-limit-redis 外置，不引 sharedCache。
    const unflagged = SINGLE_PROCESS_DEPENDENCIES.filter((d) => {
      const file = path.join(SRC_DIR, d.module);
      if (!fs.existsSync(file)) return false;
      return fs.readFileSync(file, 'utf8').includes('sharedCache') && d.redisExternalized !== true;
    }).map((d) => d.module);
    expect({ unflagged }).toEqual({ unflagged: [] });
  });
});
