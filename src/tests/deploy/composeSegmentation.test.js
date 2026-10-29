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

  test('redis 的认证口令必须来自 secret 文件，且**不得进入进程 argv**', () => {
    const block = serviceBlock('redis');
    // 可执行形态（command 列表内），不是注释里的“用法示例”
    const exec = block
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .join('\n');
    // 口令不允许以字面量出现：唯一合法形态是运行时 $(cat /run/secrets/…) 展开
    expect(exec).toMatch(/\/run\/secrets\/redis(?:\/redis_password|_password)/);
    expect(exec).toMatch(/requirepass %s/);
    // 2026-10-24 审计：`--requirepass "$(cat …)"` 经 shell 展开后，明文口令就躺在
    // PID 1 的 /proc/1/cmdline 里。必须走配置文件（tmpfs、umask 077）。
    expect(exec).not.toContain('--requirepass');
    expect(exec).toMatch(/umask 077/);
    expect(exec).toMatch(/exec redis-server \/tmp\/redis\.conf/);
  });

  test('redis 的 healthcheck 必须带认证，且口令走 REDISCLI_AUTH 而非 -a', () => {
    const block = serviceBlock('redis');
    const exec = block
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .join('\n');
    expect(exec).toMatch(
      /REDISCLI_AUTH="\$\$\(cat \/run\/secrets\/redis(?:\/redis_password|_password)\)" redis-cli ping \| grep -q PONG/
    );
    // -a 会把口令放进 healthcheck 进程的 argv（/proc/<pid>/cmdline）
    expect(exec).not.toMatch(/redis-cli[^\n]*\s-a\s/);
  });

  test('app 与 Redis 初始化链路都经 redis_password secret 注入', () => {
    const app = serviceBlock('app');
    expect(app).toMatch(/- REDIS_PASSWORD_FILE=\/run\/secrets\/redis_password/);
    // 顶层 secrets 段声明 + app/初始化容器挂载，缺一边 = 容器起来就缺文件。
    //（缩进用 {2}/{4} 显式量化，绕开 no-regex-spaces）
    expect(YML).toMatch(/^ {2}redis_password:\r?$/m);
    expect(YML).toMatch(/^ {4}file: \.\/secrets\/redis_password\r?$/m);
    for (const s of ['app', 'redis-secret-init']) {
      expect(serviceBlock(s)).toMatch(/- redis_password\r?/);
    }
    expect(serviceBlock('redis')).toMatch(/redis-secrets:\/run\/secrets\/redis:ro/);
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

/**
 * 端口暴露面闸门（H-1，2026-10-29 二轮渗透）
 *
 * 事故形态：被测试例的 mongod 绑在 0.0.0.0:27017 且未开 auth，任何对端可零凭据
 * 接管全库。本仓 compose 目前是 `expose`（仅容器间）而非 `publish`（到宿主机），
 * 但**没有任何断言盯着这一点**——为本地调试临时加一行 `27017:27017` 再提交，
 * 应用照常能跑，暴露面静默扩大，与 Redis 认证那条的失效形态完全同类。
 *
 * 两条闸：
 *   1. 任何 publish 到宿主机的端口都必须绑 127.0.0.1（裸 `3000:3000` 等于 0.0.0.0）；
 *   2. mongo / redis 一律不得 publish，只允许 expose 自己的端口。
 *
 * 能力边界：静态文本断言，不跑真实 docker；「能不能起」仍由演练覆盖。
 */
describe('compose 端口暴露面闸门', () => {
  /** 去掉整行注释：注释里常写示例端口（mongo 段就有一句"可临时改为 127.0.0.1:27017:27017"） */
  const stripComments = (text) =>
    text
      .split(/\r?\n/)
      .filter((line) => !line.trim().startsWith('#'))
      .join('\n');

  /**
   * 取某服务 ports: 下的条目（支持块状与内联 `ports: [...]` 两种写法）
   *
   * 必须容忍 `ports: !override`：热升级的备色服务（app-green）用它把继承来的
   * 端口**替换**掉（extends 对 sequences 是合并，不加 !override 会同时 publish
   * 3000 与 3001）。不认这个形态时，解析结果会是「没有端口」——闸门于是
   * 对着一个 publish 了端口的服务报「干净」，正是它本该拦住的那类假绿。
   */
  const publishedPorts = (block) => {
    const lines = stripComments(block).split(/\r?\n/);
    const out = [];
    let inPorts = false;
    let portsIndent = -1;
    for (const line of lines) {
      const inline = /^(\s*)ports:\s*(?:!override\s*)?\[(.+)\]\s*$/.exec(line);
      if (inline) {
        out.push(
          ...inline[2]
            .split(',')
            .map((s) => s.trim().replace(/^['"]|['"]$/g, ''))
            .filter(Boolean)
        );
        continue;
      }
      const blockStart = /^(\s*)ports:\s*(?:!override\s*)?$/.exec(line);
      if (blockStart) {
        inPorts = true;
        portsIndent = blockStart[1].length;
        continue;
      }
      if (!inPorts) continue;
      if (line.trim() === '') continue;
      const indent = line.match(/^\s*/)[0].length;
      if (indent <= portsIndent) {
        inPorts = false;
        continue;
      }
      out.push(
        line
          .trim()
          .replace(/^-\s*/, '')
          .replace(/^['"]|['"]$/g, '')
      );
    }
    return out;
  };

  test('前提自证：五个对外服务都能解析出 publish 端口（解析器退化时下面的断言是空集假绿）', () => {
    for (const s of ['app', 'app-green', 'prometheus', 'alertmanager', 'grafana']) {
      expect(publishedPorts(serviceBlock(s)).length).toBeGreaterThan(0);
    }
  });

  test('任何 publish 到宿主机的端口都必须绑 127.0.0.1（裸端口等于 0.0.0.0）', () => {
    const offenders = [];
    // app-green 必须在内：它是热升级窗口内唯一新增的暴露面，
    // 写成 `3001:3001` 就等于给备色开了 0.0.0.0 入口，而它只在升级时才存在，
    // 平时没人会注意到
    for (const s of ['app', 'app-green', 'prometheus', 'alertmanager', 'grafana']) {
      for (const entry of publishedPorts(serviceBlock(s))) {
        if (!entry.startsWith('127.0.0.1:')) offenders.push(`${s}: ${entry}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  test('mongo / redis 只 expose 不 publish（H-1 的形态就是把 27017 publish 出去）', () => {
    expect(publishedPorts(serviceBlock('mongo'))).toEqual([]);
    expect(publishedPorts(serviceBlock('redis'))).toEqual([]);
    expect(stripComments(serviceBlock('mongo'))).toMatch(/^\s*expose:\s*$/m);
    expect(stripComments(serviceBlock('mongo'))).toContain("'27017'");
    expect(stripComments(serviceBlock('redis'))).toMatch(/^\s*expose:\s*$/m);
    expect(stripComments(serviceBlock('redis'))).toContain("'6379'");
  });

  test('全文件不得出现数据面端口的宿主映射（含 0.0.0.0 与裸端口两种写法）', () => {
    const exec = stripComments(YML);
    for (const pattern of [/27017:27017/, /6379:6379/, /0\.0\.0\.0:27017/, /0\.0\.0\.0:6379/]) {
      expect(exec).not.toMatch(pattern);
    }
  });
});
