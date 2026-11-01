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
   * 必须容忍 `ports: !override`：升级的备色服务（app-green）用它把继承来的
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
    // app-green 必须在内：它是升级窗口内唯一新增的暴露面，
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

  // ── 宿主端口互斥：热升级备色 vs 监控栈（第四轮审计 D6） ────────────────────
  //
  // 缺陷本体：app-green 固定 publish 127.0.0.1:3001（scripts/hotUpgradePolicy.js 的
  // PORT_BY_COLOR.green 与 deployment/nginx.conf.example 的备色 upstream 都钉这一条），
  // 而 grafana 也 publish 同一个宿主 3001 且在默认栈里 ⇒ 升级第 2 步
  // 「docker compose --profile green up -d --no-deps app-green」直接报
  // "Bind for 127.0.0.1:3001 failed: port is already allocated"：旧色继续服务
  // （fail-closed），但升级窗口从一开始就走不完。
  //
  // 判据：同一宿主端口不得被「可能同时在线」的两个服务声明——
  //   任一方是默认服务（无 profiles），或两方 profiles 相交 ⇒ 冲突；
  //   两方都带 profile 且集合不相交 ⇒ 只有人显式同时启用才会撞，视为互斥成立。
  // 修法选定 grafana 进 observability profile：改动最小，且端口数字不变，
  // docs/architecture.md 的宿主端口表仍然成立；runbook 与 nginx 示例同步说明。
  describe('宿主端口互斥闸门', () => {
    /** 服务块里 profiles: 的取值（默认服务 = 空数组；支持内联与块状两种写法） */
    const profilesOf = (block) => {
      const lines = stripComments(block).split(/\r?\n/);
      const out = [];
      for (let i = 0; i < lines.length; i += 1) {
        const inline = /^\s*profiles:\s*\[(.+)\]\s*$/.exec(lines[i]);
        if (inline) {
          out.push(
            ...inline[1]
              .split(',')
              .map((one) => one.trim().replace(/^['"]|['"]$/g, ''))
              .filter(Boolean)
          );
          continue;
        }
        if (!/^\s*profiles:\s*$/.test(lines[i])) continue;
        const indent = lines[i].match(/^\s*/)[0].length;
        for (let j = i + 1; j < lines.length; j += 1) {
          const line = lines[j];
          if (!line.trim()) continue;
          if (line.match(/^\s*/)[0].length <= indent) break;
          out.push(
            line
              .trim()
              .replace(/^-\s*/, '')
              .replace(/^['"]|['"]$/g, '')
          );
        }
      }
      return out;
    };

    /** '127.0.0.1:3001:3000' 或 '3001:3000' → 宿主端口号；其它形态返回 null */
    const hostPortOf = (entry) => {
      const m = /^(?:127\.0\.0\.1:)?(\d+):(\d+)$/.exec(entry.trim());
      return m ? Number(m[1]) : null;
    };

    /** 解析任意 compose 文本 → [{ name, profiles, hostPorts }] */
    const servicePortMap = (text) => {
      const lines = text.split(/\r?\n/);
      const start = lines.findIndex((line) => /^services:\s*$/.test(line));
      if (start < 0) return [];
      const blocks = [];
      let cur = null;
      for (let i = start + 1; i < lines.length; i += 1) {
        const line = lines[i];
        if (/^[A-Za-z]/.test(line)) break; // 下一个顶层段
        const m = /^ {2}([A-Za-z0-9][A-Za-z0-9_-]*):\s*$/.exec(line);
        if (m) {
          cur = { name: m[1], lines: [] };
          blocks.push(cur);
          continue;
        }
        if (cur) cur.lines.push(line);
      }
      return blocks.map(({ name, lines: body }) => {
        const blockText = body.join('\n');
        return {
          name,
          profiles: profilesOf(blockText),
          hostPorts: publishedPorts(blockText)
            .map(hostPortOf)
            .filter((port) => port !== null),
        };
      });
    };

    /** 「可能同时在线」判定：任一方默认、或 profiles 相交 ⇒ 冲突 */
    const portConflicts = (services) => {
      const conflicts = [];
      for (let i = 0; i < services.length; i += 1) {
        for (let j = i + 1; j < services.length; j += 1) {
          const a = services[i];
          const b = services[j];
          const shared = a.hostPorts.filter((port) => b.hostPorts.includes(port));
          if (shared.length === 0) continue;
          const hasDefault = a.profiles.length === 0 || b.profiles.length === 0;
          const overlap = a.profiles.some((profile) => b.profiles.includes(profile));
          if (hasDefault || overlap) {
            conflicts.push(...shared.map((port) => port + ': ' + a.name + ' ↔ ' + b.name));
          }
        }
      }
      return conflicts;
    };

    test('前提自证：五个对外服务都解析出宿主端口（解析器退化时下面全是空集假绿）', () => {
      const map = servicePortMap(YML);
      const byName = Object.fromEntries(map.map((svc) => [svc.name, svc.hostPorts]));
      expect(byName.app).toEqual([3000]);
      expect(byName['app-green']).toEqual([3001]);
      expect(byName.grafana).toEqual([3001]);
      expect(byName.prometheus).toEqual([9090]);
      expect(byName.alertmanager).toEqual([9093]);
      const profiles = Object.fromEntries(map.map((svc) => [svc.name, svc.profiles]));
      expect(profiles.app).toEqual([]);
      expect(profiles['app-green']).toEqual(['green']);
    });

    test('当前 compose 不存在「可能同时在线」的宿主端口冲突（默认栈与升级窗口各自成立）', () => {
      expect(portConflicts(servicePortMap(YML))).toEqual([]);
    });

    test('grafana 必须留在 observability profile：否则它与备色同抢 3001', () => {
      const map = servicePortMap(YML);
      const grafana = map.find((svc) => svc.name === 'grafana');
      expect(grafana.hostPorts).toEqual([3001]);
      expect(grafana.profiles).toEqual(['observability']);
      // 与备色的 profile 必须不相交：落在同一个 profile 里时，--profile 一开就撞
      const green = map.find((svc) => svc.name === 'app-green');
      expect(green.profiles).toEqual(['green']);
      for (const profile of grafana.profiles) {
        expect(green.profiles).not.toContain(profile);
      }
    });

    test('可证伪：删掉 grafana 的 profile、或让 profile 与备色重叠，判据都必须报冲突', () => {
      const fixture = (grafanaBody) =>
        [
          'services:',
          '  app:',
          '    ports:',
          "      - '127.0.0.1:3000:3000'",
          '  app-green:',
          "    profiles: ['green']",
          '    ports:',
          "      - '127.0.0.1:3001:3000'",
          '  grafana:',
          ...grafanaBody.map((line) => '    ' + line),
          'networks:',
          '  fire-safety-net:',
          '    driver: bridge',
          '',
        ].join('\n');
      const grafanaPorts = ['ports:', "  - '127.0.0.1:3001:3000'"];
      // ① 现状形态（profile 不同）→ 无冲突
      expect(
        portConflicts(servicePortMap(fixture(["profiles: ['observability']", ...grafanaPorts])))
      ).toEqual([]);
      // ② 删掉 profile（正是 D6 的旧形态）→ 必须报 3001 冲突
      expect(portConflicts(servicePortMap(fixture(grafanaPorts)))).toEqual([
        '3001: app-green ↔ grafana',
      ]);
      // ③ profile 与备色重叠 → 同时启用两个 profile 时仍会撞
      expect(
        portConflicts(servicePortMap(fixture(["profiles: ['green']", ...grafanaPorts])))
      ).toEqual(['3001: app-green ↔ grafana']);
      // ④ 挪到 3002：另一条合法修法也必须判为无冲突（判据不绑定具体端口号）
      expect(
        portConflicts(
          servicePortMap(
            fixture(["profiles: ['observability']", 'ports:', "  - '127.0.0.1:3002:3000'"])
          )
        )
      ).toEqual([]);
    });
  });
});
