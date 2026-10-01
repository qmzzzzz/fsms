/**
 * compose 分段与 Redis 认证合同（2026-10-01 审计 finding：redis 无任何认证 +
 * 六服务共处一张扁平 bridge）
 *
 * 为什么要测一个 compose：这两条的失效形态都是「看得见的配置改回去」——
 * 有人觉得 requirepass 麻烦删掉 auth 参数、或者新服务图省事直接挂 data-net，
 * 应用照常能跑（redis 无认证时一切正常），安全能力静默归零。本文件把
 * 「认证必须存在」「数据面必须收窄」钉成结构断言，改回去就红。
 *
 * 能力边界（如实说明）：静态断言，不跑真实 docker；「能不能起」由
 * deployment/rollback-drill.md 演练覆盖。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const YML = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');

/** 取某个 service 的文本块（从 `  <name>:` 到下个顶层键），用于「断言它在该服务内」 */
function serviceBlock(name) {
  const start = YML.indexOf(`\n  ${name}:`);
  if (start < 0) throw new Error(`未找到 service：${name}`);
  const rest = YML.slice(start + 1);
  const next = rest.slice(1).search(/\n {2}[a-zA-Z0-9_-]+:/);
  return next < 0 ? rest : rest.slice(0, next + 1);
}

describe('compose 数据面分段与 Redis 认证合同', () => {
  test('前提自证：六个服务块都能解析到（解析器退化时下面的断言是空集假绿）', () => {
    for (const s of ['app', 'mongo', 'redis', 'prometheus', 'alertmanager', 'grafana']) {
      expect(() => serviceBlock(s)).not.toThrow();
    }
  });

  // ── Redis 认证 ──────────────────────────────────────────────────────────

  test('redis 的 command 必须带 requirepass，且口令读自挂载的 secret 文件（不进字面量/environment）', () => {
    const block = serviceBlock('redis');
    // 可执行形态（command 列表内），不是注释里的“用法示例”
    const exec = block
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .join('\n');
    expect(exec).toContain('--requirepass');
    expect(exec).toContain('/run/secrets/redis_password');
    // 口令不允许以字面量出现：唯一合法形态是运行时 $(cat …) 展开
    expect(exec).toMatch(/requirepass "\$\$\(cat \/run\/secrets\/redis_password\)"/);
  });

  test('redis 的 healthcheck 必须带认证（否则 requirepass 开启后健康检查必挂）', () => {
    const block = serviceBlock('redis');
    const exec = block
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .join('\n');
    expect(exec).toMatch(
      /redis-cli --no-auth-warning -a "\$\$\(cat \/run\/secrets\/redis_password\)" ping \| grep -q PONG/
    );
  });

  test('app 侧凭据经 REDIS_PASSWORD_FILE 注入，且两个服务都挂 redis_password secret', () => {
    const app = serviceBlock('app');
    expect(app).toMatch(/- REDIS_PASSWORD_FILE=\/run\/secrets\/redis_password/);
    // 顶层 secrets 段声明 + 两个消费服务挂载，缺一边 = 容器起来就缺文件
    //（缩进用 {2}/{4} 显式量化，绕开 no-regex-spaces）
    expect(YML).toMatch(/^ {2}redis_password:\r?$/m);
    expect(YML).toMatch(/^ {4}file: \.\/secrets\/redis_password\r?$/m);
    for (const s of ['app', 'redis']) {
      expect(serviceBlock(s)).toMatch(/- redis_password\r?/);
    }
  });

  // ── 数据面分段 ──────────────────────────────────────────────────────────

  test('data-net 必须 internal: true（不接宿主 NAT、不出外网）', () => {
    const networks = YML.slice(YML.indexOf('\nnetworks:'));
    expect(networks).toMatch(/^ {2}data-net:\r?$/m);
    const block = networks.slice(networks.indexOf('data-net:'));
    expect(block).toMatch(/internal:\s*true/);
  });

  test('mongo / redis 只入 data-net；app 双网络；监控栈摸不到数据面', () => {
    // mongo 与 redis 的 networks 段只允许出现 data-net
    for (const s of ['mongo', 'redis']) {
      const block = serviceBlock(s);
      const nets = block.slice(block.indexOf('networks:'));
      expect(nets).toMatch(/- data-net/);
      expect(nets).not.toMatch(/- fire-safety-net/);
    }
    // app 必须双网络（出网/发布面 + 数据面），缺一边就是断链而不是隔离
    const appNets = serviceBlock('app').slice(serviceBlock('app').indexOf('networks:'));
    expect(appNets).toMatch(/- fire-safety-net/);
    expect(appNets).toMatch(/- data-net/);
    // 监控栈三件套不得入 data-net（否则分段形同虚设）
    for (const s of ['prometheus', 'alertmanager', 'grafana']) {
      const block = serviceBlock(s);
      const nets = block.slice(block.indexOf('networks:'));
      expect(nets).not.toMatch(/- data-net/);
    }
  });
});
