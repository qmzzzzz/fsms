/**
 * OpenAPI 分组声明闸：operation 里出现的每个 tag 都必须在 `spec.tags` 里声明
 *
 * 失效形态（2026-10-31 第七轮审计 D4 实测）：6 条 `/api/permissions/grants*` 的 operation 用了
 * `['Privileges']`，而 `spec.tags` 只声明了 10 个 ⇒ Swagger UI 里多出一个没有描述、也没归入
 * 已知分组的"幽灵分组"，而**没有任何门禁读 tags**（当时 `git grep -n "tags" -- src/tests` 零命中）：
 * `scripts/check-openapi-drift.js` 只比对生成器与产物的 path / method / 定义，不比对分组声明。
 *
 * 判据三条（两条方向相反 + 一条对齐）：
 *   ① 用到的 tag 必须都已声明（未声明 ⇒ 红）；
 *   ② 声明的 tag 必须都被用到（死声明 ⇒ 红：有人改了 operation 的分组却忘了删声明）；
 *   ③ README 的「N 个模块」必须等于 `spec.tags` 条数——数字不写进测试，现读产物，
 *      于是"文档里的数字"和"产物里的声明"只能一起变。
 * 前提自证：路径表必须真的读到（path / operation / tag 数量有下界），否则空集对空集也会绿。
 *
 * 事实来源是**已提交产物** `src/docs/openapi.json`。它与生成器的一致性由
 * `src/tests/docs/openapiSync.test.js`（生成器 ↔ 产物逐条一致）与 `npm run docs:check` 兜住，
 * 本文件只判"声明面"这一件事，不重复对账 path / method。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const SPEC_FILE = path.join(ROOT, 'src', 'docs', 'openapi.json');
const README_FILE = path.join(ROOT, 'README.md');

const spec = JSON.parse(fs.readFileSync(SPEC_FILE, 'utf8'));
const declared = (spec.tags || []).map((t) => t.name);
const used = new Set();
let operations = 0;
for (const pathKey of Object.keys(spec.paths)) {
  for (const method of Object.keys(spec.paths[pathKey])) {
    operations += 1;
    for (const tag of spec.paths[pathKey][method].tags || []) used.add(tag);
  }
}

describe('OpenAPI 分组声明闸（spec.tags ⊇ 用到的 tag）', () => {
  test('前提自证：真的读到了路径与分组（空集不算通过）', () => {
    expect(declared.length).toBeGreaterThanOrEqual(8);
    expect(operations).toBeGreaterThanOrEqual(100);
    expect(used.size).toBeGreaterThanOrEqual(8);
  });

  test('① 每个用到的 tag 都已声明（未声明 ⇒ Swagger UI 出现幽灵分组）', () => {
    expect([...used].filter((t) => !declared.includes(t)).sort()).toEqual([]);
  });

  test('② 每个声明的 tag 都被用到（死声明即红）', () => {
    expect(declared.filter((t) => !used.has(t)).sort()).toEqual([]);
  });

  test('③ README 的三个数字 = spec 现读实数（模块数/path/operation，只能一起变）', () => {
    const readme = fs.readFileSync(README_FILE, 'utf8');
    const m = /涵盖 (\d+) 个模块共 (\d+) 个接口（(\d+) 个 path \/ (\d+) 个 operation）/.exec(
      readme
    );
    if (!m)
      throw new Error(
        'README.md 里找不到「涵盖 N 个模块共 N 个接口（N 个 path / N 个 operation）」的计数句式'
      );
    // 三个数字逐一与产物对账：此前只钉模块数，path/operation 各漂 9 都无人看
    // （审计 H6：README 写 97/118、实测 106/127，"由测试钉住"的措辞只在模块数上成立）
    let pathCount = 0;
    let operationCount = 0;
    for (const pathKey of Object.keys(spec.paths)) {
      pathCount += 1;
      for (const method of Object.keys(spec.paths[pathKey])) {
        operationCount += 1;
      }
    }
    expect(Number(m[1])).toBe(declared.length);
    expect(Number(m[2])).toBe(operationCount);
    expect(Number(m[3])).toBe(pathCount);
    expect(Number(m[4])).toBe(operations);
  });
});
