/**
 * S-5：直接 Compose 启动的告警配置硬闸
 *
 * 缺陷形状：部署脚本会以生产口径校验 Alertmanager 配置，但绕过脚本的
 * `docker compose up -d` 直接挂载仓库占位模板 ⇒ 告警栈「健康」运行，
 * critical 全部发往 hooks.example.com，事故时无人被叫醒。
 * 修复：compose 增加一次性校验容器，alertmanager 以 service_completed_successfully
 * 依赖它；判据复用 scripts/compliance-alerting.js，不允许第二套解析口径。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts', 'check-alertmanager-config.js');
const COMPOSE = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');

const configured = () =>
  [
    'receivers:',
    '  - name: ops-critical',
    '    webhook_configs:',
    "      - url: 'https://oapi.dingtalk.com/robot/send?access_token=0f1e2d3c4b5a6978'",
    '',
  ].join('\n');

const placeholder = () =>
  [
    'receivers:',
    '  - name: ops-critical',
    '    webhook_configs:',
    "      - url: 'https://hooks.example.com/<替换为critical通知通道access_token>'",
    '',
  ].join('\n');

const staged = [];
afterAll(() => {
  for (const dir of staged) fs.rmSync(dir, { recursive: true, force: true });
});

function writeConfig(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'amcheck-'));
  staged.push(dir);
  const file = path.join(dir, 'alertmanager.yml');
  fs.writeFileSync(file, content);
  return file;
}

function run(file, extraEnv = {}) {
  const env = { ...process.env, ALLOW_PLACEHOLDER_ALERT_WEBHOOK: '', ...extraEnv };
  return spawnSync(process.execPath, [SCRIPT, file], { env, encoding: 'utf8' });
}

describe('S-5 告警配置启动闸：直接 Compose 不再能带占位通道运行', () => {
  test('已注入真实通道 → 放行', () => {
    const r = run(writeConfig(configured()));
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('通过');
  });

  test('仓库占位模板 → 拒绝启动，并给出两条可执行路径', () => {
    const r = run(writeConfig(placeholder()));
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('拒绝启动');
    expect(r.stderr).toContain('ALERTMANAGER_CONFIG_PATH');
    expect(r.stderr).toContain('ALLOW_PLACEHOLDER_ALERT_WEBHOOK=true');
  });

  test('演练环境显式豁免 → 放行但必须打印「无人会被叫醒」', () => {
    const r = run(writeConfig(placeholder()), { ALLOW_PLACEHOLDER_ALERT_WEBHOOK: 'true' });
    expect(r.status).toBe(0);
    expect(r.stderr).toContain('告警不会触达任何人');
  });

  test('误配（明文 http）任何豁免声明都不放行', () => {
    const misconfigured = configured().replace('https://oapi', 'http://oapi');
    const r = run(writeConfig(misconfigured), { ALLOW_PLACEHOLDER_ALERT_WEBHOOK: 'true' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('仓库态同样为红');
  });

  test('配置读不到 → 拒绝启动（判不了按不过处理）', () => {
    const r = run(path.join(os.tmpdir(), 'amcheck-does-not-exist.yml'));
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('无法读取');
  });
});

describe('S-5 Compose 接线：校验容器必须真正挡在 alertmanager 前面', () => {
  const alertmanagerBlock = () => {
    const i = COMPOSE.indexOf('\n  alertmanager:');
    expect(i).toBeGreaterThan(-1);
    const next = COMPOSE.indexOf('\n  grafana:', i);
    return COMPOSE.slice(i, next === -1 ? undefined : next);
  };

  test('alertmanager 依赖校验成功（不是 started，也不是没接）', () => {
    const block = alertmanagerBlock();
    expect(block).toMatch(
      /alertmanager-config-check:\s*\n\s*condition:\s*service_completed_successfully/
    );
  });

  test('校验源与运行源是同一个文件（ALERTMANAGER_CONFIG_PATH 同时进入两处挂载）', () => {
    const i = COMPOSE.indexOf('\n  alertmanager-config-check:');
    const j = COMPOSE.indexOf('\n  alertmanager:', i);
    expect(i).toBeGreaterThan(-1);
    const checkBlock = COMPOSE.slice(i, j);
    const mount =
      /\$\{ALERTMANAGER_CONFIG_PATH:-\.\/deployment\/observability\/alertmanager\.yml\}/;
    expect(checkBlock).toMatch(mount);
    expect(alertmanagerBlock()).toMatch(mount);
  });

  test('校验容器挂载的脚本存在且镜像为 digest 钉死引用', () => {
    const i = COMPOSE.indexOf('\n  alertmanager-config-check:');
    const j = COMPOSE.indexOf('\n  alertmanager:', i);
    const block = COMPOSE.slice(i, j);
    expect(block).toMatch(/image:\s*node:26\.12\.0-alpine@sha256:[0-9a-f]{64}/);
    for (const name of [
      'check-alertmanager-config.js',
      'alertmanager-config-path.js',
      'compliance-alerting.js',
    ]) {
      expect(block).toContain(`./scripts/${name}:/check/${name}:ro`);
      expect(fs.existsSync(path.join(ROOT, 'scripts', name))).toBe(true);
    }
  });
});
