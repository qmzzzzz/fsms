/**
 * 「镜像里跑哪个 Node，矩阵里就得测哪个 Node」（2026-10-24）
 *
 * 缺陷本体：Dockerfile 三个 FROM 全是 `node:26.12.0-alpine`（生产实际运行时），
 * 而 ci.yml 的 test 矩阵是 `[22.x, 24.x]`——**发布到生产的那条运行时从未被任何
 * CI 用例执行过**。当时 ci.yml 里有一句注释承认「26.x 尚未进矩阵」，但注释不是闸门：
 * 下一个人把镜像升到 28 时同样只会留下第二句注释。
 *
 * 为什么必须由测试而不是注释来守：这类分叉的两种方向都无声无息——
 *   · 升级镜像不同步矩阵 ⇒ 新运行时零覆盖（22/24 全绿，26/28 上的差异上线才发现）；
 *   · 收窄矩阵不同步镜像 ⇒ 声明支持的最低线不再被实测。
 * 两者的共同点是「两边各自都合法」，所以只能靠一条跨文件断言把它们钉在一起。
 *
 * 判据三条：
 *   1. Dockerfile 每个 node FROM 的主版本都出现在 test 矩阵里；
 *   2. 三处 FROM 主版本一致（多阶段工具链漂移，与 digest 一致性同源）；
 *   3. `engines.node` 的**下界**主版本也在矩阵里（声明支持 ≠ 实测支持）。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const DOCKERFILE = read('Dockerfile');
const CI = read('.github/workflows/ci.yml');

/** Dockerfile 里所有 node FROM 的主版本（跳过注释行） */
function dockerfileNodeMajors(text) {
  const majors = [];
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*#/.test(line)) continue;
    const m = /^\s*FROM\s+node:(\d+)\.[0-9]+\.[0-9]+/.exec(line);
    if (m) majors.push(Number(m[1]));
  }
  return majors;
}

/** test job 的 node-version 矩阵主版本列表；没有数组形态的矩阵时返回 null */
function matrixMajors(text) {
  const m = /node-version:\s*\[([^\]]+)\]/.exec(text);
  if (!m) return null;
  return m[1]
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const hit = /^(\d+)\.x$/.exec(s);
      return hit ? Number(hit[1]) : NaN;
    });
}

/** `engines.node` 下界的主版本，例如 `>=22.12.0` → 22 */
function enginesLowerMajor(pkgText) {
  const m = /"node"\s*:\s*">=\s*(\d+)\./.exec(pkgText);
  return m ? Number(m[1]) : null;
}

const MATRIX = matrixMajors(CI);

describe('Node 运行时：镜像 / CI 矩阵 / engines 三者对齐', () => {
  test('解析器自证：确实读到了 FROM 与矩阵（防解析退化后断言空转）', () => {
    const majors = dockerfileNodeMajors(DOCKERFILE);
    expect(majors.length).toBe(3); // builder / web-builder / runtime
    expect(MATRIX).not.toBeNull();
    expect(MATRIX.length).toBeGreaterThanOrEqual(2);
    expect(MATRIX).toContain(22);
    expect(MATRIX).toContain(24);
  });

  test('三处 FROM 的 node 主版本一致（多阶段工具链漂移不变量）', () => {
    const majors = dockerfileNodeMajors(DOCKERFILE);
    expect([...new Set(majors)]).toHaveLength(1);
  });

  test('镜像使用的 node 主版本必须在 CI 矩阵内（否则发布基线零覆盖）', () => {
    const majors = [...new Set(dockerfileNodeMajors(DOCKERFILE))];
    const uncovered = majors.filter((m) => !MATRIX.includes(m));
    expect(uncovered).toEqual([]);
  });

  test('engines.node 的下界主版本必须在矩阵内（声明支持 ≠ 实测支持）', () => {
    for (const pkg of ['package.json', 'web-admin/package.json']) {
      const major = enginesLowerMajor(read(pkg));
      expect({ pkg, major: major !== null }).toEqual({ pkg, major: true });
      expect({ pkg, covered: MATRIX.includes(major) }).toEqual({ pkg, covered: true });
    }
  });

  test('可证伪：镜像升到矩阵外的版本时必须被报出（不是恒绿）', () => {
    const bumped = DOCKERFILE.replace(/FROM node:(\d+)\./g, 'FROM node:99.');
    expect(bumped).not.toBe(DOCKERFILE);
    const majors = [...new Set(dockerfileNodeMajors(bumped))];
    expect(majors).toEqual([99]);
    expect(majors.filter((m) => !MATRIX.includes(m))).toEqual([99]);
    // 反向：矩阵侧收窄同样必须被 engines 那条断言抓住
    expect(matrixMajors(CI.replace(/node-version:\s*\[[^\]]+\]/, 'node-version: [24.x]'))).toEqual([
      24,
    ]);
  });
});
