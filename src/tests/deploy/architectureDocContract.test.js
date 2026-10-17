/**
 * 架构文档 ↔ docker-compose 的契约（F-06，2026-10-17）
 *
 * 缺陷本体：`docs/architecture.md` 的部署拓扑图把 MongoDB 画在 `fire-safety-net` 里、
 * 与 app 同网；而实际 compose 中 mongo **只**在 `data-net`，且该网络 `internal: true`。
 * 图里还完全没有 redis、prometheus、alertmanager、grafana。
 *
 * 这类偏差的危害不是"文档不好看"：
 *   - 值班人员按图排障会连错网络（去 fire-safety-net 找 mongo，找不到）；
 *   - 安全评审无法只凭图确认"app 是否能直连数据面""监控栈能不能摸到 redis"；
 *   - 故障时容易"按图修网络"，把 `internal: true` 这条隔离边界改掉。
 *
 * 判据刻意不做成"解析 mermaid"（那等于写一个 mermaid 解析器）：只钉三件可机械核对的事——
 * ① compose 里的每个网络名都出现在文档里；② 每个服务名都出现在文档里；
 * ③ 文档把 mongo/redis 画在 data-net 分组内、把监控三件画在 fire-safety-net 分组内。
 * 第 ③ 条用 mermaid 的 `subgraph NAME[...]` 到 `end` 之间的文本切片，够用且不会误判。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const COMPOSE = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
const DOC = fs.readFileSync(path.join(ROOT, 'docs', 'architecture.md'), 'utf8');

/** 取某个顶层段（services / networks / volumes …）下的二级键名 */
function topLevelKeys(section) {
  const lines = COMPOSE.split(/\r?\n/);
  const start = lines.findIndex((l) => new RegExp(`^${section}:\\s*$`).test(l));
  if (start === -1) throw new Error(`docker-compose.yml 里找不到顶层段 ${section}:`);
  const keys = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^[a-zA-Z]/.test(line)) break; // 下一个顶层键
    const m = line.match(/^ {2}([A-Za-z0-9][A-Za-z0-9_-]*):\s*$/);
    if (m) keys.push(m[1]);
  }
  return keys;
}

/** 取 mermaid 里某个 subgraph 的正文（到配对的 end 为止） */
function subgraphBody(name) {
  const lines = DOC.split(/\r?\n/);
  const start = lines.findIndex((l) => l.includes(`subgraph ${name}[`));
  if (start === -1) return null;
  const body = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^\s*end\s*$/.test(lines[i])) break;
    body.push(lines[i]);
  }
  return body.join('\n');
}

const SERVICE_NAMES = topLevelKeys('services');
const NETWORK_NAMES = topLevelKeys('networks');

describe('F-06 架构文档与 compose 的服务清单同步', () => {
  test('compose 解析出预期的服务（解析器失效时后面全绿也没意义）', () => {
    // 反证：解析器若把 services 段读成空，下面的"每个服务都在文档里"会恒真。
    expect(SERVICE_NAMES).toEqual(
      expect.arrayContaining(['app', 'mongo', 'redis', 'prometheus', 'alertmanager', 'grafana'])
    );
  });

  test.each(['app', 'mongo', 'redis', 'prometheus', 'alertmanager', 'grafana'])(
    '服务 %s 在架构文档里被提到',
    (name) => {
      expect(DOC).toContain(name);
    }
  );

  test('文档里没有"只在文档里存在"的服务名（图表不得虚构组件）', () => {
    // 反向：从文档的 mermaid 节点标签里抽服务名太脆，这里只钉一个具体的历史错误——
    // 旧图把 mongo 放在 fire-safety-net 里，而 compose 的 mongo 只接 data-net。
    const dataNet = subgraphBody('DATA');
    expect(dataNet).toBeTruthy();
    expect(dataNet).toContain('MONGO');
  });
});

describe('F-06 网络名与隔离边界', () => {
  test('compose 的每个网络名都出现在文档里', () => {
    expect(NETWORK_NAMES.length).toBeGreaterThanOrEqual(2);
    for (const net of NETWORK_NAMES) {
      expect({ net, inDoc: DOC.includes(net) }).toMatchObject({ net, inDoc: true });
    }
  });

  test('data-net 在 compose 里是 internal: true，文档必须写明这一点', () => {
    const netSection = COMPOSE.slice(COMPOSE.indexOf('\nnetworks:'));
    const dataNet = netSection.slice(netSection.indexOf('data-net:'));
    expect(dataNet).toMatch(/internal:\s*true/);
    // 文档侧：隔离语义必须可读，不能只画一条线
    expect(DOC).toContain('internal: true');
    expect(DOC).toContain('不接宿主 NAT');
  });

  test('mongo / redis 画在数据面分组，监控三件画在边缘分组（旧图把 mongo 画在 fire-safety-net）', () => {
    const dataNet = subgraphBody('DATA');
    const edge = subgraphBody('EDGE');
    expect(dataNet).toBeTruthy();
    expect(edge).toBeTruthy();
    // 数据面：只有 mongo 与 redis
    expect(dataNet).toContain('MONGO');
    expect(dataNet).toContain('REDIS');
    expect(dataNet).not.toContain('PROM');
    expect(dataNet).not.toContain('GRAF');
    // 边缘面：监控三件，且不含 mongo/redis（这是旧图的错处）
    expect(edge).toContain('PROM');
    expect(edge).toContain('AM');
    expect(edge).toContain('GRAF');
    expect(edge).not.toContain('MONGO');
    expect(edge).not.toContain('REDIS');
  });

  test('app 双网络接入在文档里被显式说明（含"为什么"）', () => {
    expect(DOC).toContain('双网络接入');
    expect(DOC).toContain('唯一的数据面访问者');
    // 新服务不要顺手加进 data-net —— 这条注释是给下一个人看的，必须留在文档里
    expect(DOC).toContain('不要顺手把它加进');
  });
});

describe('F-06 宿主端口表与 compose 一致', () => {
  test('文档列出的每个 127.0.0.1 端口都真的在 compose 里发布', () => {
    const published = [...COMPOSE.matchAll(/'127\.0\.0\.1:(\d+):(\d+)'/g)].map((m) => m[1]);
    expect(published.length).toBeGreaterThanOrEqual(4);
    for (const port of published) {
      expect({ port, inDoc: DOC.includes(`127.0.0.1:${port}`) }).toMatchObject({
        port,
        inDoc: true,
      });
    }
  });
});
