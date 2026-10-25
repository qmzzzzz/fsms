/**
 * app 服务的健康检查归属契约（2026-10-24）
 *
 * 审计提法：「docker-compose.yml 的 app 服务块没有 healthcheck，而 mongo 有」。
 * 复核结论：**该形态不是漏配**，但前提必须被钉住，否则它随时会变成真缺陷。
 *
 * 事实链：
 *   - 健康检查由**镜像**提供（Dockerfile 的 `HEALTHCHECK --interval=30s ...`）；
 *   - Compose 在服务未声明 healthcheck 时原样继承镜像里的那一条；
 *   - mongo / redis 之所以在 compose 里写，是因为它们的官方镜像不带 HEALTHCHECK。
 *
 * 为什么「不要在 compose 里补一条」：镜像侧那条同时探 /readyz（让 readyz_verdict
 * 在持续运行期产生）与 /health（决定退出码），而 compose 侧手写一条通常只探
 * /health。后者一旦生效会整体顶掉镜像口径 ⇒ 容器健康、但 readyz_verdict 从不
 * 产生 ⇒ MongoUnavailable 恒不触发、ReadinessProbeMissing 对健康实例恒告警。
 * 也就是说，这个「补全」动作本身就是一次监控退化。
 *
 * 因此本文件锁的是**依赖关系**而不是某一行文本：
 *   1. app 块不声明 healthcheck（现状，且是刻意如此）；
 *   2. 镜像必须自带 HEALTHCHECK（第 1 条的全部前提）；
 *   3. 解析器自证 + 变异对照，证明第 1 条真的会红而不是空跑。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
const dockerfile = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');

/** 顶层服务块（按 2 空格缩进的 key 切分；嵌套 key 是 4 空格起，不会误切） */
function serviceBlockFrom(text, name) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => new RegExp(`^ {2}${name}:\\s*$`).test(l));
  if (start < 0) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {2}[A-Za-z0-9_.-]+:\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

/** 去掉整行注释：注释里会写「不要写 disable: true」这类文本，不能参与判定 */
const codeOnly = (block) =>
  block
    .split(/\r?\n/)
    .filter((l) => !/^\s*#/.test(l))
    .join('\n');

/** 服务块是否声明了 healthcheck（4 空格缩进的直接子键） */
const declaresHealthcheck = (block) => /^ {4}healthcheck:/m.test(codeOnly(block));

describe('app 服务不覆盖镜像的健康检查', () => {
  const block = serviceBlockFrom(compose, 'app');

  test('前提自证：确实切出了 app 服务块（防「块没切到 ⇒ 断言全绿」）', () => {
    expect(block).not.toBeNull();
    const code = codeOnly(block);
    // 三处已知指令，确认切到的是 app 块本体而不是空串/邻居块
    expect(code).toMatch(/^ {4}restart:\s*unless-stopped$/m);
    expect(code).toMatch(/^ {4}stop_grace_period:\s*30s$/m);
    expect(code).toMatch(/^ {4}read_only:\s*true$/m);
  });

  test('app 块不声明 healthcheck——健康检查必须来自镜像，不能在这里另写一条', () => {
    // 加回一条（哪怕写得"更严格"）都会顶掉镜像侧同时探 /readyz 的口径，
    // 结果是 readyz_verdict 不再产生。确需改动请先读 docker-compose.yml 该块
    // 的注释与 dockerHealthcheckReadyz.test.js，并同步本条断言。
    expect(declaresHealthcheck(block)).toBe(false);
    // 反向锚点：也不得以 disable 的形式把镜像那条关掉
    expect(codeOnly(block)).not.toMatch(/^ {6}disable:\s*true$/m);
  });

  test('镜像自带 HEALTHCHECK（上一条的全部前提；缺失即健康检查彻底不存在）', () => {
    expect(dockerfile).toMatch(/^HEALTHCHECK\s+--interval=/m);
    expect(dockerfile).not.toMatch(/HEALTHCHECK\s+NONE/);
  });

  test('对照：mongo 在 compose 里声明了 healthcheck（说明差异是刻意的，不是同一条规则漏用）', () => {
    const mongo = serviceBlockFrom(compose, 'mongo');
    expect(mongo).not.toBeNull();
    expect(declaresHealthcheck(mongo)).toBe(true);
  });

  test('解析器自证：合成的 app 块带 healthcheck 时必须被识别（否则上一条是空跑）', () => {
    const synthetic = [
      'services:',
      '  app:',
      '    image: x',
      '    healthcheck:',
      '      disable: true',
      '  mongo:',
      '    image: y',
      '',
    ].join('\n');
    const syntheticApp = serviceBlockFrom(synthetic, 'app');
    expect(syntheticApp).not.toBeNull();
    expect(declaresHealthcheck(syntheticApp)).toBe(true);
    // 且块边界正确：没有把 mongo 吞进来
    expect(codeOnly(syntheticApp)).not.toMatch(/image:\s*y/);
  });
});
