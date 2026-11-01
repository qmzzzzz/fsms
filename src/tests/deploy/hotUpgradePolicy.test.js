/**
 * 升级判据
 *
 * 这些用例守的不是「函数能跑」，而是四种「升级看起来成功、实际没成」的形态：
 *   · 镜像用浮动 tag ⇒ 审计里记的版本与线上跑的不是一回事；
 *   · upstream 两行都放开 ⇒ nginx 轮询，两个版本混跑；
 *   · upstream 一行都不放开 ⇒ 全站 502；
 *   · readyz 只看 200 ⇒ 反代把 503 改写成 200 的登录页也算「就绪」。
 */

const fs = require('fs');
const path = require('path');

const policy = require('../../../scripts/hotUpgradePolicy');

const ROOT = path.resolve(__dirname, '../../..');
const NGINX_EXAMPLE = path.join(ROOT, 'deployment/nginx.conf.example');
const DIGEST = `sha256:${'a'.repeat(64)}`;

const wrap = (servers) =>
  ['http {', '    upstream fsms_app {', ...servers.map((s) => `        ${s}`), '    }', '}'].join(
    '\n'
  );

describe('镜像引用必须 digest 钉扎', () => {
  test('接受 registry/repo@sha256:<64hex>', () => {
    const parsed = policy.parseImageRef(`ghcr.io/qmzzzzz/fsms@${DIGEST}`);
    expect(parsed.repository).toBe('ghcr.io/qmzzzzz/fsms');
    expect(parsed.digest).toBe(DIGEST);
  });

  test('拒绝 tag 形态（tag 可被覆盖，无法证明线上跑的是审计里记的那一版）', () => {
    expect(() => policy.parseImageRef('ghcr.io/qmzzzzz/fsms:v1.2.3')).toThrow(/digest 钉扎/);
    expect(() => policy.parseImageRef('ghcr.io/qmzzzzz/fsms:latest')).toThrow(/digest 钉扎/);
  });

  test('拒绝畸形 digest 与空值', () => {
    expect(() => policy.parseImageRef('ghcr.io/x/y@sha256:short')).toThrow(/digest 格式非法/);
    expect(() => policy.parseImageRef('ghcr.io/x/y@sha256:' + 'A'.repeat(64))).toThrow(
      /digest 格式非法/
    );
    expect(() => policy.parseImageRef('')).toThrow(/镜像引用为空/);
    expect(() => policy.parseImageRef(undefined)).toThrow(/镜像引用为空/);
  });
});

describe('镜像白名单', () => {
  const parsed = policy.parseImageRef(`ghcr.io/qmzzzzz/fsms@${DIGEST}`);

  test('命中前缀则放行', () => {
    expect(policy.assertImageAllowed(parsed, ['ghcr.io/qmzzzzz/'])).toBe(true);
    expect(policy.assertImageAllowed(parsed, ['ghcr.io/qmzzzzz/fsms'])).toBe(true);
  });

  test('空白名单 = 全拒（升级器默认不得接受任意镜像）', () => {
    expect(() => policy.assertImageAllowed(parsed, [])).toThrow(/白名单为空/);
    expect(() => policy.assertImageAllowed(parsed, ['  ', ''])).toThrow(/白名单为空/);
  });

  test('前缀必须落在路径分隔符上：不得让 fsms-evil 冒充 fsms', () => {
    const evil = policy.parseImageRef(`ghcr.io/qmzzzzz/fsms-evil@${DIGEST}`);
    expect(() => policy.assertImageAllowed(evil, ['ghcr.io/qmzzzzz/fsms'])).toThrow(/不在白名单/);
  });

  test('其它组织的镜像被拒', () => {
    expect(() => policy.assertImageAllowed(parsed, ['ghcr.io/someoneelse/'])).toThrow(/不在白名单/);
  });
});

describe('upstream 活动色解析', () => {
  test('真实模板：当前是 blue / 3000，且只声明了两行', () => {
    const active = policy.parseActiveUpstream(fs.readFileSync(NGINX_EXAMPLE, 'utf8'));
    expect(active.color).toBe('blue');
    expect(active.port).toBe(3000);
    expect(active.declared.map((d) => d.port).sort()).toEqual([3000, 3001]);
  });

  test('两行都放开 ⇒ 报错（轮询混跑比 502 更危险：能跑但语义错乱）', () => {
    const conf = wrap(['server 127.0.0.1:3000;', 'server 127.0.0.1:3001;']);
    expect(() => policy.parseActiveUpstream(conf)).toThrow(/2 行未注释/);
  });

  test('一行都不放开 ⇒ 报错（全站 502）', () => {
    const conf = wrap(['# server 127.0.0.1:3000;', '# server 127.0.0.1:3001;']);
    expect(() => policy.parseActiveUpstream(conf)).toThrow(/0 行未注释/);
  });

  test('没有 upstream 块 ⇒ 报错，不猜目标地址', () => {
    expect(() => policy.parseActiveUpstream('server { listen 80; }')).toThrow(/找不到.*upstream/);
  });

  test('未知端口 ⇒ 报错（端口与颜色的对应关系只在一处定义）', () => {
    const conf = wrap(['server 127.0.0.1:9999;']);
    expect(() => policy.parseActiveUpstream(conf)).toThrow(/不是已知色/);
  });
});

describe('upstream 切流写入', () => {
  const original = fs.readFileSync(NGINX_EXAMPLE, 'utf8');

  test('切到 green 后恰好一行未注释，且解析回 green', () => {
    const next = policy.renderUpstream(original, 'green');
    const active = policy.parseActiveUpstream(next);
    expect(active.color).toBe('green');
    expect(active.port).toBe(3001);
  });

  test('幂等：对已是目标色的文本再写一次，逐字节相同（失败重试不会写成第三种形态）', () => {
    const once = policy.renderUpstream(original, 'green');
    const twice = policy.renderUpstream(once, 'green');
    expect(twice).toBe(once);
  });

  test('只动 upstream 块内的 server 行，其它字节原样保留', () => {
    const next = policy.renderUpstream(original, 'green');
    const a = original.split('\n');
    const b = next.split('\n');
    expect(b.length).toBe(a.length);

    const changed = a.map((line, i) => (line === b[i] ? null : i)).filter((i) => i !== null);
    // 只有两行 server 会变（一行加注释、一行去注释）
    expect(changed.length).toBeLessThanOrEqual(2);
    for (const i of changed) {
      expect(a[i]).toMatch(/server\s+127\.0\.0\.1:300[01]/);
    }
  });

  test('CRLF 文本回写后仍是 CRLF（Windows checkout 的文件不得被悄悄改成 LF）', () => {
    // 先归一成 LF 再转 CRLF：模板本身在 Windows checkout 下就是 CRLF，
    // 直接 `\n → \r\n` 会得到 `\r\r\n`（行尾残留 \r 会让行级正则整体失配）
    const crlf = original.replace(/\r\n/g, '\n').replace(/\n/g, '\r\n');
    const next = policy.renderUpstream(crlf, 'green');
    expect(next).toContain('\r\n');
    expect(/(?<!\r)\n/.test(next)).toBe(false);
    expect(policy.parseActiveUpstream(next).color).toBe('green');
  });

  test('目标端口不在块内 ⇒ 报错，不写半成品配置', () => {
    const conf = wrap(['server 127.0.0.1:3000;']);
    expect(() => policy.renderUpstream(conf, 'green')).toThrow(/没有端口 3001/);
  });
});

describe('readyz 判定', () => {
  test('200 + status=ready 才算就绪', () => {
    expect(policy.evaluateReadyz(200, { status: 'ready' })).toEqual({ ok: true, reason: 'ready' });
  });

  test('200 + unready 不算就绪，且把未通过的检查项带出来', () => {
    const r = policy.evaluateReadyz(200, {
      status: 'unready',
      checks: { mongo: 'ok', redis: 'timeout', transactions: 'standalone' },
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('redis=timeout');
    expect(r.reason).toContain('transactions=standalone');
  });

  test('503 不算就绪（即使 body 写着 ready）', () => {
    expect(policy.evaluateReadyz(503, { status: 'ready' }).ok).toBe(false);
  });

  test('非 JSON 响应不算就绪（反代把 503 改写成 200 的 HTML 时就是这个形态）', () => {
    const r = policy.evaluateReadyz(200, null);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/不是 JSON/);
  });
});

describe('命令行解析', () => {
  test('默认是演练：不给 --apply 时 apply=false', () => {
    const opts = policy.parseArgs(['--image', `ghcr.io/x/y@${DIGEST}`]);
    expect(opts.apply).toBe(false);
    expect(opts.dryRun).toBe(false);
    expect(opts.readyzTimeoutSec).toBe(policy.DEFAULT_OPTIONS.readyzTimeoutSec);
  });

  test('--apply 与 --image= 内联写法都支持', () => {
    const opts = policy.parseArgs([`--image=ghcr.io/x/y@${DIGEST}`, '--apply']);
    expect(opts.apply).toBe(true);
    expect(opts.image).toBe(`ghcr.io/x/y@${DIGEST}`);
  });

  test('--status-file 供宿主代理回写进度；缺省为空串', () => {
    const opts = policy.parseArgs(['--status-file', '/var/lib/fsms/upgrade/status/a.json']);
    expect(opts.statusFile).toBe('/var/lib/fsms/upgrade/status/a.json');
    expect(policy.parseArgs([]).statusFile).toBe('');
  });

  test('未知参数必须报错：`--dryrun` 被静默忽略就等于真的去改生产', () => {
    expect(() => policy.parseArgs(['--dryrun'])).toThrow(/未知参数/);
  });

  test('缺值必须报错', () => {
    expect(() => policy.parseArgs(['--image'])).toThrow(/需要一个值/);
    expect(() => policy.parseArgs(['--image', '--apply'])).toThrow(/需要一个值/);
  });

  test('数值参数拒绝非整数与负数', () => {
    expect(() => policy.parseArgs(['--observe-seconds', 'abc'])).toThrow(/整数/);
    expect(() => policy.parseArgs(['--readyz-timeout', '-1'])).toThrow(/整数/);
  });

  test('--apply=false / --dry-run=false 必须被读成 false（不是「出现过就为真」）', () => {
    // 反例场景真实存在：workflow/模板里写 --apply=${{ inputs.apply }}，值为 false 时
    // 旧实现照样执行切流。这条钉住的是「参数写 false 时绝不改生产」。
    expect(policy.parseArgs(['--apply=false']).apply).toBe(false);
    expect(policy.parseArgs(['--apply=false']).dryRun).toBe(false);
    expect(policy.parseArgs(['--dry-run=false']).dryRun).toBe(false);
    expect(policy.parseArgs(['--apply=true']).apply).toBe(true);
    expect(policy.parseArgs(['--apply=1']).apply).toBe(true);
    expect(policy.parseArgs(['--apply=0']).apply).toBe(false);
    expect(policy.parseArgs(['--apply']).apply).toBe(true);
  });

  test('布尔旗标给了无法解释的值时报错，而不是猜一个', () => {
    expect(() => policy.parseArgs(['--apply=maybe'])).toThrow(/布尔值/);
    expect(() => policy.parseArgs(['--dry-run=off'])).toThrow(/布尔值/);
  });
});
describe('部署配置与脚本的契约（静态闸门）', () => {
  test('nginx 模板必须定义 upstream fsms_app，且不得再出现直连 3000 的 proxy_pass', () => {
    const src = fs.readFileSync(NGINX_EXAMPLE, 'utf8');
    expect(src).toMatch(/upstream\s+fsms_app\s*\{/);
    // 留着直连就等于「切流后仍有一半请求打到旧色」
    expect(src).not.toMatch(/proxy_pass\s+http:\/\/127\.0\.0\.1:3000/);
  });

  test('compose 备色服务只在 green profile 下存在，且镜像变量与脚本约定一致', () => {
    const src = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');
    expect(src).toMatch(/app-green:/);
    expect(src).toMatch(/profiles:\s*\['green'\]/);
    expect(src).toMatch(/APP_IMAGE_NEXT/);
    // extends 对 sequences 是合并而非替换：没有 !override 会同时 publish 3000 与 3001
    expect(src).toMatch(/ports:\s*!override/);
  });
});
