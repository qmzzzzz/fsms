/**
 * F-214：fire-and-forget 告警投递只许有一个入口，且那个入口不得静默
 *
 * 缺陷形状（2026-09-27 实测定位）：`securityAlert.js:170-185` 把
 * `dispatchNotification` 的注释写成「fire-and-forget 投递的统一入口」，
 * 内部三个检测器也确实在用它 —— 但它**没有导出**。于是外部的调用方
 * （`middleware/security.js` 的黑名单命中通知）只能用同一模块导出的裸
 * `sendNotification`，写成 `void sendNotification(...)`，而裸函数没有 reject 兜底。
 *
 * 为什么"外面包一层 try/catch"救不了它（这是本条最容易被看错的地方）：
 * `async` 函数不抛异常，它返回 rejected promise ⇒ 调用点的 `try` 永远接不住，
 * 于是那句「通知失败不影响拦截主流程」的注释在裸 void 下**不成立** ——
 * 它命中的是 `index.js:436-453` 的 unhandledRejection 分支，
 * 而那条分支在**所有环境**都 `process.exit(1)`：黑名单拦截路径变成整机重启。
 * （今天不可达：投递函数在 `try` 之前没有可抛点，逐条读过。所以补的是
 *  "统一入口"这个既定契约，不是无据防御的空 catch。）
 *
 * 四只闸，各自单独可证伪（变异实测见台账 107）：
 *  ① 全仓生产码：`sendNotification(` 的调用点只许出现在"带 .catch 的统一入口"
 *     或"await"两种形态里 —— 少一个 catch 就红，多一个绕过入口的文件也红；
 *  ② 入口必须被导出（否则下一个外部调用方还会重犯同一个错）；
 *  ③ 黑名单通知这一点确实走入口；
 *  ④ 行为面：底层 reject 时必须**记 error 日志**（`.catch(() => {})` 这种静默
 *     形状正是入口注释自己反对的那件事），并带成功路径作对照臂。
 *
 * ①②③ 跑在 jsCodeOnly 的"只剩代码"视图上：注释不该能把闸骗绿，也不该骗红。
 */

const fs = require('fs');
const path = require('path');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');

/** 读某个仓内文件并剥成代码视图 */
const codeView = (rel) => jsCodeOnly(fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8'));

/** src 下的生产码（排除 src/tests 自身） */
function productionFiles(dir) {
  const out = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (full === path.join(REPO_ROOT, 'src', 'tests')) continue;
      out.push(...productionFiles(full));
    } else if (ent.name.endsWith('.js')) {
      out.push(path.relative(REPO_ROOT, full).split(path.sep).join('/'));
    }
  }
  return out;
}

/** 某文件代码视图里所有含 `sendNotification(` 的行（连同"是否合规"） */
function callLines(rel) {
  return codeView(rel)
    .split('\n')
    .filter((l) => l.includes('sendNotification('));
}

/** 合规调用点：带 .catch 的统一入口本体，或显式 await */
const isHandledCall = (line) =>
  line.includes('.catch(') || /await\s+(?:[\w$]+\.)*sendNotification\s*\(/.test(line);

describe('F-214 fire-and-forget 告警投递的单一入口', () => {
  const ENTRY_FILE = 'src/services/securityAlert.js';
  const AWAITER_FILE = 'src/services/auditMonitor.js';
  // 第二个 await 侧调用点（2026-09-30 新增审计链周期核验时引入）：同 auditMonitor 的
  // 口径——它要拿投递结果做自己的记账（lastAlertFingerprint / 当日配额），
  // 所以走 `await sendNotification(...)` 这条显式形态，而不是 fire-and-forget 入口。
  // 登记在这里正是本闸的设计意图：新增调用点必须显式表态"它怎么接住 promise"。
  const CHAIN_MONITOR_FILE = 'src/services/auditChainMonitor.js';
  const BLACKLIST_CALLER = 'src/middleware/security.js';

  describe('① 全仓生产码：没有第二处丢弃 promise 的 sendNotification 调用', () => {
    test('列出所有含裸调用串的文件，并逐行判定"有没有被接住"', () => {
      const hits = productionFiles(path.join(REPO_ROOT, 'src'))
        .map((rel) => ({ rel, lines: callLines(rel) }))
        .filter((e) => e.lines.length > 0);

      // 白名单式断言：新增调用点必须在这里显式登记它是怎么接住 promise 的
      expect(hits.map((e) => e.rel).sort()).toEqual(
        [ENTRY_FILE, AWAITER_FILE, CHAIN_MONITOR_FILE].sort()
      );

      const unhandled = hits.flatMap((e) =>
        e.lines.filter((l) => !isHandledCall(l)).map((l) => `${e.rel}: ${l.trim()}`)
      );
      expect(unhandled).toEqual([]);
    });

    /**
     * 对照臂：本闸必须是"能红"的。把已修复前的形状（void + 无 catch）喂给判据，
     * 它必须判为不合规 —— 否则上面的 `toEqual([])` 只是因为判据恒真。
     */
    test('对照臂：`void sendNotification(...)`（无 catch）被同一判据判为不合规', () => {
      expect(isHandledCall('void sendNotification(a, b, c, d);')).toBe(false);
      expect(isHandledCall('sendNotification(a);')).toBe(false);
      // 反向：合规的两种形态确实合规
      expect(isHandledCall('void sendNotification(a).catch((e) => log(e));')).toBe(true);
      expect(isHandledCall('await securityAlert.sendNotification(a, b);')).toBe(true);
    });
  });

  describe('②③ 入口对外可见，且黑名单通知走的是它', () => {
    test('dispatchNotification 出现在 module.exports 里（否则外部只能绕开入口）', () => {
      const src = codeView(ENTRY_FILE);
      const from = src.indexOf('module.exports');
      expect(from).toBeGreaterThan(-1);
      expect(src.slice(from)).toMatch(/\bdispatchNotification\b/);
    });

    test('middleware/security.js 的黑名单通知调用入口本体，且不再出现裸调用串', () => {
      const src = codeView(BLACKLIST_CALLER);
      expect(src).toMatch(/\bdispatchNotification\s*\(/);
      expect(src).not.toMatch(/\bsendNotification\s*\(/);
    });
  });

  describe('④ 行为面：底层 reject 必须留下 error 日志（不得静默）', () => {
    /** 以指定投递实现重新装配 securityAlert 门面，并返回它 + logger 的 error 探针 */
    const loadFacade = (sendImpl) => {
      jest.resetModules();
      jest.doMock('../../services/securityAlertDelivery', () => ({
        sendNotification: sendImpl,
        isWebhookTargetAllowed: () => true,
      }));
      const securityAlert = require('../../services/securityAlert');
      const logger = require('../../utils/logger');
      const spy = jest.spyOn(logger, 'error').mockImplementation(() => logger);
      return { dispatch: securityAlert.dispatchNotification, spy };
    };

    afterEach(() => {
      jest.restoreAllMocks();
      jest.dontMock('../../services/securityAlertDelivery');
      jest.resetModules();
    });

    test('入口是函数（②的导出不是死键名）', () => {
      const { dispatch } = loadFacade(jest.fn().mockResolvedValue(undefined));
      expect(typeof dispatch).toBe('function');
    });

    test('reject 时记一条带告警类型的 error（"告警机器自己崩了"必须可见）', async () => {
      const { dispatch, spy } = loadFacade(jest.fn().mockRejectedValue(new Error('日志器不可用')));
      dispatch('unit_probe_type', 'critical', '探针消息', { probe: true });
      await new Promise((resolve) => setTimeout(resolve, 0));
      const msgs = spy.mock.calls.map((c) => String(c[0]));
      expect(msgs.some((m) => m.includes('unit_probe_type'))).toBe(true);
    });

    test('对照臂：投递成功时不得出现该 error（上一条不是恒真）', async () => {
      const { dispatch, spy } = loadFacade(jest.fn().mockResolvedValue(undefined));
      dispatch('unit_probe_ok', 'critical', '探针消息', { probe: true });
      await new Promise((resolve) => setTimeout(resolve, 0));
      const msgs = spy.mock.calls.map((c) => String(c[0]));
      expect(msgs.some((m) => m.includes('unit_probe_ok'))).toBe(false);
    });
  });
});
