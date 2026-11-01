/**
 * 迁移导读表门禁：migrations/README.md 的「回滚语义一览」必须逐条覆盖 migrations/*.js
 *
 * 失效形态（2026-10-31 第七轮审计 D7 实测）：那张表是**手工维护**的——README 自己在文末
 * 写着"没有门禁兜底，新增迁移必须自己补一行"。于是漏补一行时任何东西都不会变红，而运维回滚前
 * 读的正是这份导读：漏一行 = "这次迁移的回滚语义没人写下来"，且没有任何信号。
 *
 * 判据两条，方向相反、缺一不可：
 *   ① 目录里每个 migrations/*.js 都必须在表里有行（漏行 ⇒ 红）；
 *   ② 表里每一行都必须指向真实存在的迁移文件（僵尸行 ⇒ 红，防表退化成历史账本）；
 *   ③ README 自报的「现有 N 个迁移」必须等于实测文件数——数字漂移与漏行是同一个坑的两面，
 *      句式被改坏（抠不到数字）同样报红，不静默通过（与 architectureDocContract 的 documentedCount 同口径）。
 * 外加前提自证：解析器必须真的解析到表行、真的数到文件——否则正则写坏会退化成"空集对空集也通过"
 * （testTreePurity 的同一课）。
 *
 * 边界：本文件只核"存在性 + 数量"，**不**判定 down() 到底撤不撤得动——那只能读迁移文件头
 * （migrations/README.md 自己也这么说），本文件不假装能自动判定。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const MIGRATIONS_DIR = path.join(ROOT, 'migrations');
const README_FILE = path.join(MIGRATIONS_DIR, 'README.md');

/** 迁移文件名的形状：`<14 位时间戳>-<snake-名称>.js` */
const MIGRATION_NAME_RE = /^\d{14}-[A-Za-z0-9-]+\.js$/;

/**
 * 只解析「回滚语义一览」这一节里、第一列形如迁移文件名的行。
 * 为什么要限定到节：README 里还有别的表（`npm run migrate:*` 命令表），它们的首列
 * 同样是反引号包裹的字符串——不限定就会把 `npm run migrate:up` 当成一行迁移，
 * 于是判据 ② 在干净仓库上也报红（本条写在前提自证里）。
 */
function parseSemanticsRows(text) {
  const start = text.search(/^##\s*回滚语义一览/m);
  if (start < 0) throw new Error('migrations/README.md 里找不到「回滚语义一览」小节');
  const rest = text.slice(start + 1);
  const next = rest.search(/^##\s/m);
  const section = next < 0 ? rest : rest.slice(0, next);
  const rows = new Map();
  for (const line of section.split(/\r?\n/)) {
    const m = /^\|\s*`([^`]+)`\s*\|/.exec(line.trim());
    if (m && MIGRATION_NAME_RE.test(m[1])) rows.set(m[1], line.trim());
  }
  return rows;
}

describe('migrations/README.md 回滚语义表 ⊇ migrations/*.js', () => {
  const readme = fs.readFileSync(README_FILE, 'utf8');
  const rows = parseSemanticsRows(readme);
  const entries = fs.readdirSync(MIGRATIONS_DIR, { withFileTypes: true });
  const files = entries
    .filter((e) => e.isFile() && e.name.endsWith('.js'))
    .map((e) => e.name)
    .sort();

  test('前提自证：真的解析到表行、真的数到迁移文件（空集不算通过）', () => {
    expect(files.length).toBeGreaterThanOrEqual(8);
    expect(rows.size).toBeGreaterThanOrEqual(8);
    // 反证：命令表里的首列（`npm run migrate:up` 之类）必须被形状过滤掉，
    // 否则判据 ② 会把它们当成僵尸行（干净仓库上就红）
    expect([...rows.keys()].every((r) => MIGRATION_NAME_RE.test(r))).toBe(true);
    // 反证：目录里除 *.js 外还有 README.md，说明上面的筛选真的在筛
    expect(entries.some((e) => e.isFile() && !e.name.endsWith('.js'))).toBe(true);
  });

  test('① 目录里每个迁移文件都在表里有行（漏一行即红）', () => {
    const missing = files.filter((f) => !rows.has(f));
    expect(missing).toEqual([]);
  });

  test('② 表里每一行都指向真实存在的迁移文件（僵尸行即红）', () => {
    const zombies = [...rows.keys()].filter(
      (ref) => !fs.existsSync(path.join(MIGRATIONS_DIR, ref))
    );
    expect(zombies).toEqual([]);
  });

  test('③ README 自报的迁移数 = 实测文件数（数字漂移即红）', () => {
    const m = /现有 \*\*(\d+) 个迁移\*\*/.exec(readme);
    if (!m) throw new Error('migrations/README.md 里找不到「现有 N 个迁移」的计数句式');
    expect(Number(m[1])).toBe(files.length);
  });
});
