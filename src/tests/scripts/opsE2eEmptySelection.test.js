/**
 * 空选集必须失败（`scripts/ops-e2e.js` 的假绿回归门禁）。
 *
 * ## 为什么需要这条
 * `--only ","` 这类写法按逗号 split + filter 之后得到**空数组**，而空数组在 JS 里是
 * 真值 ⇒ `args.only ? JOURNEYS.filter(...) : JOURNEYS` 的 false 分支永不成立 ⇒ 四条
 * 旅程全被排除，汇总打印 `0/0 通过` 并 **退 0**。消费者是
 * `.github/workflows/ci.yml` 里的 `npm run test:ops-e2e`——发布门禁上写歪一个参数，
 * 就能拿到"四条关键路径全过"的绿。
 *
 * ## 判据与同仓对照
 * 同族缺陷在 `scripts/verify-image-digests.js` 已被显式堵住（"命中 0 行期望表…
 * 拒绝把空跑报成通过"）。本套件把那句纪律钉在 ops-e2e 上：**空选集一律非 0**。
 *
 * ## 变异实测（红先绿后）
 * 把 `parseArgs` 里的 `if (ids.length === 0)` 分支与 `main()` 里的
 * `selected.length === 0` 兜底一并删除（即还原成修复前的写法），本套件 3 条断言
 * 全部转红（实测：CLI 退 0 且打印 "0/0 通过"）。恢复后全绿。
 *
 * ## 为什么真的 spawn 一次
 * 假绿发生在**退出码**上，而退出码只有真跑进程才看得见；只测 `parseArgs` 会漏掉
 * "parseArgs 拦了、main 又把它吞了"这一族。子进程在参数校验阶段就退出，
 * 不起内存 Mongo、不跑任何旅程，单次 < 1s。
 */

const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const SCRIPT = path.join(ROOT, 'scripts', 'ops-e2e.js');

/** 被测对象的真实现（不许在本文件里复刻一份参数解析） */
const { JOURNEYS, JOURNEY_IDS, parseArgs, EMPTY_SELECTION_MESSAGE } = require(SCRIPT);

/** 真跑一次 CLI，返回 { status, out } */
function runCli(args) {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 30000,
  });
  return { status: r.status, out: (r.stdout || '') + (r.stderr || '') };
}

describe('ops-e2e：空选集不是通过（假绿回归）', () => {
  test('前提自证：旅程表与话术都在，且空数组确实是真值（本缺陷的成因）', () => {
    expect(JOURNEYS).toHaveLength(4);
    expect(JOURNEY_IDS).toEqual([
      'alert-delivery',
      'deploy-rollback',
      'backup-restore',
      'cross-department',
    ]);
    expect(EMPTY_SELECTION_MESSAGE).toBe('选择器命中 0 条，拒绝把空跑报成通过');
    // 这条不是废话：`args.only ? ... : ...` 之所以漏掉空集，正是因为 [] 在 JS 里为真值。
    expect(Boolean([])).toBe(true);
  });

  // 变异实测：删掉 parseArgs 里的 ids.length === 0 分支 ⇒ args.errors 为空 ⇒ 本条红。
  test('parseArgs：`--only ","` 必须报错（split+filter 后为空不是"全选"）', () => {
    for (const raw of [',', ' , ', ', ,']) {
      const args = parseArgs(['--only', raw]);
      expect(args.errors).toHaveLength(1);
      expect(args.errors[0]).toContain(EMPTY_SELECTION_MESSAGE);
      // 报错时必须点名用户写的那个取值，否则读了也不知道该改哪里
      expect(args.errors[0]).toContain(JSON.stringify(raw));
      // 关键：不许顺手把 only 设成空数组（那正是修复前的形态）
      expect(args.only).toBeNull();
    }
  });

  test('parseArgs：正常写法不受影响（防"为了堵空集把正常路径也堵死"）', () => {
    const one = parseArgs(['--only', 'backup-restore']);
    expect(one.errors).toEqual([]);
    expect(one.only).toEqual(['backup-restore']);
    const two = parseArgs(['--only', 'backup-restore, alert-delivery']);
    expect(two.errors).toEqual([]);
    expect(two.only).toEqual(['backup-restore', 'alert-delivery']);
    const all = parseArgs([]);
    expect(all.errors).toEqual([]);
    expect(all.only).toBeNull(); // 不传 --only = 全选，这条路径必须保持
    expect(parseArgs(['--list']).errors).toEqual([]);
  });

  // 变异实测：删掉 main() 里的 selected.length === 0 兜底（同时保留 parseArgs 分支）时
  // 本条的**第一段**仍绿、第二段（--only 空集）仍红——两处判据各自独立可证伪。
  test('CLI：空选集必须非 0，且打印"拒绝把空跑报成通过"', () => {
    const { status, out } = runCli(['--only', ',']);
    expect(status).not.toBe(0);
    expect(out).toContain(EMPTY_SELECTION_MESSAGE);
    // 修复前的形态是这两行：它们是本条的反向判据
    expect(out).not.toContain('0/0 通过');
  });

  test('CLI：`--only` 里全是未知旅程同样非 0（防把"未知"当成"空集"静默通过）', () => {
    const { status, out } = runCli(['--only', 'nope,also-nope']);
    expect(status).not.toBe(0);
    expect(out).toContain('未知旅程');
  });

  test('CLI：正常单旅程仍在参数校验后继续（不许把 exit 0 的合法路径改红）', () => {
    const { status, out } = runCli(['--only', 'backup-restore', '--list']);
    expect(status).toBe(0);
    expect(out).toContain('可用旅程');
    expect(out).not.toContain(EMPTY_SELECTION_MESSAGE);
  });
});
