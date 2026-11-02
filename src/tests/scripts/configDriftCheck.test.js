'use strict';

/**
 * 部署面配置漂移检测（M-05）用例
 *
 * 三件事必须同时成立，否则这类脚本只是"看起来在设防"：
 *   ① 抽面有效：安全标志、TLS 指令、安全相关环境键都真的被抽到（反向：无关键不得入账）；
 *   ② 判据有牙齿：改值/删项/加项各自被识别，且**不输出取值**（模板里可能夹带密钥样例）；
 *   ③ 基线不撒谎：仓库当前状态与已提交基线一致——改了 compose 的安全标志而不 --update 就红。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { collectItems, diffItems, loadBaseline } = require('../../../scripts/config-drift-check');

const ROOT = path.resolve(__dirname, '../../..');

const COMPOSE = [
  'services:',
  '  app:',
  '    read_only: true',
  '    cap_drop:',
  '      - ALL',
  '    security_opt:',
  '      - no-new-privileges:true',
  '    networks:',
  '      - edge',
  '  db:',
  '    read_only: false',
  '    privileged: !override',
  '    networks:',
  '      - data',
].join('\n');

const DOCKERFILE = [
  'FROM node:20',
  'USER nodejs',
  'HEALTHCHECK CMD node -e "process.exit(0)"',
].join('\n');

const NGINX = [
  'ssl_protocols TLSv1.2 TLSv1.3;',
  'ssl_prefer_server_ciphers off;',
  'add_header Strict-Transport-Security "max-age=63072000" always;',
  'server_tokens off;',
  'client_max_body_size 2m;',
].join('\n');

const ENV_EXAMPLE = [
  'NODE_ENV=production',
  'JWT_SECRET=change-me-not-a-real-secret',
  'BACKUP_GPG_RECIPIENT=ops@example.com',
  'TRUSTED_PROXY_CIDRS=172.28.0.0/16',
  'SOME_UNRELATED_FLAG=1',
].join('\n');

const writeFixture = (dir, overrides = {}) => {
  fs.mkdirSync(path.join(dir, 'deployment'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'docker-compose.yml'), overrides.compose || COMPOSE);
  fs.writeFileSync(path.join(dir, 'Dockerfile'), overrides.dockerfile || DOCKERFILE);
  fs.writeFileSync(path.join(dir, 'deployment/nginx.conf.example'), overrides.nginx || NGINX);
  fs.writeFileSync(path.join(dir, '.env.example'), overrides.env || ENV_EXAMPLE);
  return dir;
};

describe('部署面配置漂移检测（M-05）', () => {
  let dir;
  beforeAll(() => {
    dir = writeFixture(fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-config-drift-')));
  });
  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('抽面有效：容器标志、TLS 指令与安全相关环境键都入账', () => {
    const items = collectItems(dir);
    expect(items['compose:app:read_only']).toBeTruthy();
    expect(items['compose:app:cap_drop']).toBeTruthy();
    expect(items['compose:app:security_opt']).toBeTruthy();
    expect(items['compose:db:read_only']).toBeTruthy();
    // compose 的自定义 tag（!override）不得让整份文件解析失败
    expect(items['compose:db:privileged']).toBeTruthy();
    expect(items['dockerfile:USER']).toBeTruthy();
    expect(items['dockerfile:HEALTHCHECK']).toBeTruthy();
    expect(items['nginx:ssl_protocols']).toBeTruthy();
    expect(items['nginx:add_header Strict-Transport-Security']).toBeTruthy();
    expect(items['env-example:JWT_SECRET']).toBeTruthy();
    expect(items['env-example:BACKUP_GPG_RECIPIENT']).toBeTruthy();
  });

  test('反向对照：无关配置不进账面，取值只以摘要形式出现（不落明文）', () => {
    const items = collectItems(dir);
    expect(items['env-example:SOME_UNRELATED_FLAG']).toBeUndefined();
    expect(items['nginx:client_max_body_size']).toBeUndefined();
    for (const digest of Object.values(items)) expect(digest).toMatch(/^[0-9a-f]{16}$/);
    expect(JSON.stringify(items)).not.toContain('change-me-not-a-real-secret');
    expect(JSON.stringify(items)).not.toContain('ops@example.com');
  });

  test('判据有牙齿：改值 / 删项 / 加项各自被识别，且只报条目名', () => {
    const before = collectItems(dir);
    expect(diffItems(before, before)).toEqual([]);

    const changedDir = writeFixture(
      fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-config-changed-')),
      {
        compose: COMPOSE.replace('read_only: true', 'read_only: false'),
      }
    );
    const changed = diffItems(before, collectItems(changedDir));
    expect(changed).toEqual([{ item: 'compose:app:read_only', status: 'changed' }]);

    const removedDir = writeFixture(
      fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-config-removed-')),
      {
        nginx: NGINX.replace('server_tokens off;\n', '').replace(
          'ssl_protocols TLSv1.2 TLSv1.3;',
          ''
        ),
      }
    );
    const removed = diffItems(before, collectItems(removedDir));
    expect(removed.map((entry) => entry.status)).toEqual(['removed', 'removed']);
    expect(removed.map((entry) => entry.item)).toEqual([
      'nginx:server_tokens',
      'nginx:ssl_protocols',
    ]);

    const addedDir = writeFixture(fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-config-added-')), {
      env: ENV_EXAMPLE + '\nMFA_ENFORCE_ALL=true',
    });
    const added = diffItems(before, collectItems(addedDir));
    expect(added).toEqual([{ item: 'env-example:MFA_ENFORCE_ALL', status: 'added' }]);
    for (const entry of [...changed, ...removed, ...added]) {
      expect(Object.keys(entry).sort()).toEqual(['item', 'status']);
    }

    for (const cleanup of [changedDir, removedDir, addedDir]) {
      fs.rmSync(cleanup, { recursive: true, force: true });
    }
  });

  test('基线不撒谎：仓库当前配置面与已提交基线一致（改了 compose 而不 --update 即红）', () => {
    const baseline = loadBaseline();
    expect(baseline).toBeTruthy();
    expect(Object.keys(baseline).length).toBeGreaterThanOrEqual(50);
    expect(Object.keys(baseline)).toContain('compose:app:read_only');
    expect(diffItems(baseline, collectItems(ROOT))).toEqual([]);
  });

  test('CLI 契约：仓库内执行退出码 0，且 --json 输出可被机器消费', () => {
    const run = spawnSync(process.execPath, ['scripts/config-drift-check.js', '--json'], {
      cwd: ROOT,
      encoding: 'utf8',
    });
    expect(run.status).toBe(0);
    const parsed = JSON.parse(run.stdout);
    expect(parsed.drift).toEqual([]);
    expect(parsed.baselineItems).toBeGreaterThanOrEqual(50);
  });

  /**
   * 同一条指令在模板里出现多份是常态：443 的 server、80/跳转的 server、以及另一处
   * vhost 各下一份安全头。原实现逐行 `items[key] = digest(本行)` 是**覆盖赋值**，
   * 账面上只剩最后一份 ⇒ 前面几份被人改掉/摘掉时闸照样绿。
   * 下面这组用例连同旁边的公平性对照一起成立才叫「有牙齿」：
   *   · 改第 1 / 2 / 3 份 ⇒ 各自都要报 changed；
   *   · 整行注释掉中间那份 ⇒ 要报（配置面少了一处下发点）；
   *   · **什么都不改 ⇒ 必须报无漂移**（否则「处处报漂移」也能让上面几条全绿）；
   *   · 改动与账面无关的指令 ⇒ 必须报无漂移（防「一切皆漂移」的假牙齿）。
   */
  test('覆盖赋值回归：同一指令的每一份副本都必须在同一份摘要里', () => {
    const multi = [
      'server {',
      '  listen 443 ssl;',
      '  server_tokens off;',
      '  add_header Strict-Transport-Security "max-age=63072000" always;',
      '  add_header X-Frame-Options SAMEORIGIN;',
      '}',
      'server {',
      '  listen 80;',
      '  server_tokens off;',
      '  add_header Strict-Transport-Security "max-age=63072000" always;',
      '  add_header X-Frame-Options SAMEORIGIN;',
      '}',
      'server {',
      '  listen 8443 ssl;',
      '  server_tokens off;',
      '  add_header Strict-Transport-Security "max-age=63072000" always;',
      '  add_header X-Frame-Options SAMEORIGIN;',
      '  client_max_body_size 2m;',
      '}',
    ].join('\n');

    const dirs = [];
    const itemsOf = (nginx) => {
      const d = writeFixture(fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-config-copies-')), {
        nginx,
      });
      dirs.push(d);
      return collectItems(d);
    };
    const hsts = 'add_header Strict-Transport-Security';
    const lines = multi.split('\n');
    const hstsAt = lines.reduce(
      (acc, l, i) => (l.trim().startsWith(hsts) ? acc.concat(i) : acc),
      []
    );
    expect(hstsAt.length).toBe(3);
    const before = itemsOf(multi);

    const driftOf = (nginx) => diffItems(before, itemsOf(nginx));
    const mutate = (index, fn) => {
      const ls = lines.slice();
      ls[index] = fn(ls[index]);
      return ls.join('\n');
    };

    // 公平性对照①：一个字都不改时必须是空漂移
    expect(driftOf(multi)).toEqual([]);

    // 公平性对照②：改与账面无关的指令不得产生漂移（防「一切皆漂移」）
    expect(driftOf(multi.replace('client_max_body_size 2m;', 'client_max_body_size 8m;'))).toEqual(
      []
    );

    // 三份副本逐个被改（降级到不带 always）：每一份都必须被看见
    for (const index of hstsAt) {
      const degraded = mutate(index, (line) => line.replace(/always;\s*$/, ';'));
      expect({ line: index + 1, drift: driftOf(degraded) }).toEqual({
        line: index + 1,
        drift: [{ item: 'nginx:' + hsts, status: 'changed' }],
      });
    }

    // 整行注释掉中间那份：配置面少了一处下发点，同样必须报
    const commented = mutate(hstsAt[1], (line) => '# ' + line);
    expect(driftOf(commented)).toEqual([{ item: 'nginx:' + hsts, status: 'changed' }]);

    // 新增第 4 份副本：多出一处下发点是有意的信号，不是误报
    const extra = multi + '\nadd_header Strict-Transport-Security "max-age=63072000" always;\n';
    expect(driftOf(extra)).toEqual([{ item: 'nginx:' + hsts, status: 'changed' }]);

    // 摘要口径的形状：同一指令多份时，键仍然只有一个（不是「第 n 份」拆键）
    expect(Object.keys(before).filter((k) => k.startsWith('nginx:' + hsts)).length).toBe(1);

    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });
});
