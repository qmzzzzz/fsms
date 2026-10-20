'use strict';

const fs = require('fs');
const path = require('path');
const { assert, createJourney, runNode } = require('../lib');
const { REQUIRED_SECRET_FILES } = require('../../deployPolicy');

const REQUIRED_MARKERS = [
  '备份先于迁移、迁移先于切换',
  '自动回滚切回上一镜像并复检就绪',
  '已应用迁移时拒绝自动回滚',
];
const TARGET_IMAGE = 'ghcr.io/qmzzzzz/fsms:sha-ops-target';
const PREVIOUS_IMAGE = 'ghcr.io/qmzzzzz/fsms:sha-ops-previous';

function makeStage(root, tmpDir, name) {
  const dir = path.join(tmpDir, 'deploy-rollback', name);
  const secrets = path.join(dir, 'secrets');
  fs.mkdirSync(secrets, { recursive: true });
  for (const secret of REQUIRED_SECRET_FILES) {
    const value = secret === 'mongodb_uri' ? 'mongodb://127.0.0.1:27017/ops_e2e' : `v-${secret}`;
    fs.writeFileSync(path.join(secrets, secret), `${value}\n`);
  }
  const alertmanager = path.join(dir, 'alertmanager.yml');
  fs.writeFileSync(
    alertmanager,
    [
      'receivers:',
      '  - name: ops-critical',
      '    webhook_configs:',
      "      - url: 'https://oapi.dingtalk.com/robot/send?access_token=0f1e2d3c4b5a6978'",
      '  - name: ops-warning',
      '    webhook_configs:',
      "      - url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=0f1e2d3c4b5a6978'",
      '',
    ].join('\n')
  );
  return { dir, secrets, alertmanager, log: path.join(dir, 'cmd.log') };
}

function buildRules(root, { readyz, migrateOutput }) {
  const compose = `docker compose -f ${path.join(root, 'docker-compose.yml')}`;
  return [
    `curl|${readyz}|0`,
    `docker inspect|${PREVIOUS_IMAGE}|0`,
    `${compose} ps -q app|fake-container-id|0`,
    `${compose} run --rm --no-deps app node node_modules/.bin/migrate-mongo up|${migrateOutput}|0`,
    '*||0',
  ].join('\n');
}

function runDeploy(root, stage, { readyz, migrateOutput }) {
  fs.writeFileSync(stage.log, '');
  const hook = path.join(root, 'src', 'tests', 'deploy', 'helpers', 'stubExec.js');
  const nodeOptions = process.env.NODE_OPTIONS ? `${process.env.NODE_OPTIONS} ` : '';
  return runNode(path.join(root, 'scripts', 'deploy.js'), [], {
    timeoutMs: 30000,
    env: {
      ...process.env,
      NODE_OPTIONS: `${nodeOptions}--require "${hook.replace(/\\/g, '/')}"`,
      STUB_LOG: stage.log,
      STUB_LOG_ENV: 'APP_IMAGE',
      STUB_RESPONSES: buildRules(root, { readyz, migrateOutput }),
      STUB_SECRETS_DIR: stage.secrets,
      APP_IMAGE: TARGET_IMAGE,
      CORS_ORIGIN: 'https://admin.example.com',
      ALLOWED_HOSTS: 'fsms.example.com',
      ALERTMANAGER_CONFIG_PATH: stage.alertmanager,
      BACKUP_RPO_HOURS: '24',
      BACKUP_RTO_HOURS: '4',
      DEPLOY_HEALTH_TIMEOUT_MS: '200',
      DEPLOY_ROLLBACK_TIMEOUT_MS: '200',
      DEPLOY_PROBE_PORT: '3999',
    },
  });
}

function readCommands(stage) {
  return fs.readFileSync(stage.log, 'utf8').split(/\r?\n/).filter(Boolean);
}

function indexOfCommand(commands, needle) {
  return commands.findIndex((line) => line.includes(needle));
}

function countCommands(commands, needle) {
  return commands.filter((line) => line.includes(needle)).length;
}

async function main(config) {
  const { root, tmpDir } = config;
  const journey = createJourney('deploy-rollback', REQUIRED_MARKERS);

  let rollbackResult = null;
  let rollbackCommands = [];
  await journey.step('备份先于迁移、迁移先于切换（健康失败后自动回滚）', async () => {
    const stage = makeStage(root, tmpDir, 'rollback');
    rollbackResult = runDeploy(root, stage, { readyz: '@seq:503,200', migrateOutput: '' });
    rollbackCommands = readCommands(stage);
    assert.equal(rollbackResult.status, 1, `部署失败路径应退出 1，实得 ${rollbackResult.status}`);
    assert.match(rollbackResult.stdout, /本次没有待应用的迁移/);
    assert.match(rollbackResult.stdout, /\[回滚决策\] 健康门禁未通过且存在上一版本镜像/);

    const backup = indexOfCommand(rollbackCommands, 'backup-mongo.sh');
    const migrate = indexOfCommand(rollbackCommands, 'migrate-mongo up');
    const firstSwitch = indexOfCommand(rollbackCommands, 'up -d --no-build app');
    assert.ok(backup >= 0, '未执行备份');
    assert.ok(migrate >= 0, '未执行迁移');
    assert.ok(firstSwitch >= 0, '未切换容器');
    assert.ok(backup < migrate, '备份必须早于迁移');
    assert.ok(migrate < firstSwitch, '迁移必须早于切换');
    assert.equal(
      countCommands(rollbackCommands, 'up -d --no-build app'),
      2,
      '健康失败且无迁移时应恰好切换两次（发布 + 回滚）'
    );
  });

  await journey.step('自动回滚切回上一镜像并复检就绪', async () => {
    assert.ok(rollbackResult, '前置步骤未完成');
    assert.match(rollbackResult.stdout, new RegExp(`\\[回滚\\] 切回上一镜像：${PREVIOUS_IMAGE}`));
    assert.match(rollbackResult.stdout, /✓ 回滚后服务就绪/);
    const switches = rollbackCommands.filter((line) => line.includes('up -d --no-build app'));
    assert.equal(switches.length, 2);
    assert.match(
      switches[1],
      new RegExp(`\\[APP_IMAGE=${PREVIOUS_IMAGE}\\]`),
      '回滚切换必须显式使用上一镜像'
    );
    assert.doesNotMatch(
      switches[0],
      new RegExp(`\\[APP_IMAGE=${PREVIOUS_IMAGE}\\]`),
      '首次切换不应使用上一镜像'
    );
  });

  await journey.step('已应用迁移时拒绝自动回滚（转人工，不制造已恢复假象）', async () => {
    const stage = makeStage(root, tmpDir, 'migrated');
    const result = runDeploy(root, stage, {
      readyz: '503',
      migrateOutput: 'MIGRATED UP: 20261020-ops-e2e.js',
    });
    assert.equal(result.status, 1, `部署失败路径应退出 1，实得 ${result.status}`);
    assert.match(result.stdout, /本次应用 1 个迁移/);
    assert.match(result.stdout, /已应用 1 个数据库迁移/);
    assert.match(result.stdout, /\[回滚决策\].*不执行/);
    assert.doesNotMatch(result.stdout, /\[回滚\] 切回上一镜像/);
    assert.equal(
      countCommands(readCommands(stage), 'up -d --no-build app'),
      1,
      '有迁移时不得再执行回滚切换'
    );
  });

  return journey.finish();
}

module.exports = { main, makeStage, buildRules, runDeploy, readCommands, REQUIRED_MARKERS };
