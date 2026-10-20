/**
 * A-6：Alertmanager 配置路径的单一解析口径
 *
 * 缺陷：部署预检、合规检查、compose 校验容器各自决定「读哪份 alertmanager.yml」。
 * 部署路径认 ALERTMANAGER_CONFIG_PATH、合规检查硬编码仓库模板、容器脚本自成一套
 * 兜底——同一套判据可能对着不同的文件下结论。最直接的后果是：生产把真实配置
 * 指向 ALERTMANAGER_CONFIG_PATH 后，`npm run compliance` 仍在评价仓库占位模板。
 *
 * 本套件固定两件事：
 *   1. resolver 的优先级：显式环境变量（trim 后非空）> 调用方缺省值；
 *   2. 三条读取路径确实共用它——尤其合规检查会在进程内实际打开 env 指向的文件。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const {
  resolveAlertmanagerConfigPath,
  REPO_ALERTMANAGER_CONFIG_PATH,
  CONTAINER_ALERTMANAGER_CONFIG_PATH,
} = require(path.join(ROOT, 'scripts/alertmanager-config-path.js'));

const staged = [];
afterAll(() => {
  for (const dir of staged) fs.rmSync(dir, { recursive: true, force: true });
});

function writeConfig(content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'am-path-'));
  staged.push(dir);
  const file = path.join(dir, 'alertmanager.yml');
  fs.writeFileSync(file, content);
  return file;
}

const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

describe('A-6 resolver 优先级', () => {
  test('ALERTMANAGER_CONFIG_PATH 优先且两侧空白被裁掉', () => {
    expect(
      resolveAlertmanagerConfigPath({ ALERTMANAGER_CONFIG_PATH: '  /etc/am/custom.yml  ' })
    ).toBe('/etc/am/custom.yml');
  });

  test('未设置 / 空串 / 纯空白 ⇒ 回退调用方缺省值', () => {
    expect(resolveAlertmanagerConfigPath({})).toBe(REPO_ALERTMANAGER_CONFIG_PATH);
    expect(resolveAlertmanagerConfigPath({ ALERTMANAGER_CONFIG_PATH: '' })).toBe(
      REPO_ALERTMANAGER_CONFIG_PATH
    );
    expect(resolveAlertmanagerConfigPath({ ALERTMANAGER_CONFIG_PATH: '   ' })).toBe(
      REPO_ALERTMANAGER_CONFIG_PATH
    );
    expect(resolveAlertmanagerConfigPath({}, '/opt/fallback.yml')).toBe('/opt/fallback.yml');
  });

  test('仓库缺省路径确实指向被 compose 挂载的模板', () => {
    expect(REPO_ALERTMANAGER_CONFIG_PATH).toBe(
      path.join(ROOT, 'deployment', 'observability', 'alertmanager.yml')
    );
    expect(fs.existsSync(REPO_ALERTMANAGER_CONFIG_PATH)).toBe(true);
    expect(CONTAINER_ALERTMANAGER_CONFIG_PATH).toBe('/etc/alertmanager/alertmanager.yml');
  });
});

describe('A-6 三条读取路径共用同一口径', () => {
  test('部署预检、合规检查、compose 校验容器都经 resolver 取路径', () => {
    expect(read('scripts/deployPolicy.js')).toContain('readAlertmanagerConfig(env, fsImpl)');
    expect(read('scripts/compliance-check.js')).toContain(
      'resolveAlertmanagerConfigPath(process.env)'
    );
    expect(read('scripts/check-alertmanager-config.js')).toMatch(
      /resolveAlertmanagerConfigPath\(\s*process\.env,\s*CONTAINER_ALERTMANAGER_CONFIG_PATH\s*\)/
    );
  });

  test('合规检查实际打开 ALERTMANAGER_CONFIG_PATH 指向的文件（误配 ⇒ 红）', () => {
    const file = writeConfig(
      [
        'receivers:',
        '  - name: ops-critical',
        '    webhook_configs:',
        '      - url: "http://oapi.dingtalk.com/robot/send?access_token=deadbeef"',
        '',
      ].join('\n')
    );
    const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'compliance-check.js')], {
      cwd: ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        ALERTMANAGER_CONFIG_PATH: file,
        // 仓库态：默认模板是绿的；只有真的读了 env 指向的误配文件才会红
        ALERT_WEBHOOK_CHECK: '',
        COMPLIANCE_STRICT: '',
      },
    });

    expect(r.status).toBe(1);
    expect(r.stdout).toContain('告警投递端点就绪度 (alertmanager webhook)');
    expect(r.stdout).toMatch(/告警投递端点就绪度 \(alertmanager webhook\):.*(http|明文)/);
  });

  test('compose 校验容器无 argv 时认 ALERTMANAGER_CONFIG_PATH', () => {
    const file = writeConfig(
      [
        'receivers:',
        '  - name: ops-critical',
        '    webhook_configs:',
        "      - url: 'https://oapi.dingtalk.com/robot/send?access_token=0f1e2d3c4b5a6978'",
        '',
      ].join('\n')
    );
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, 'scripts', 'check-alertmanager-config.js')],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          ALERTMANAGER_CONFIG_PATH: file,
          ALLOW_PLACEHOLDER_ALERT_WEBHOOK: '',
        },
      }
    );

    expect(r.status).toBe(0);
    expect(r.stdout).toContain('通过');
  });
});
