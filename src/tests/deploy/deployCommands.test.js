/**
 * 部署命令拼装（O-5）：每条外发命令的完整 argv 逐项钉住
 *
 * 为什么需要这一层：审计指出 Actions 工作流从未真实执行，而 deploy.js 的命令
 * 拼装原先内联在执行函数里，现有断言只能证明「输出里出现过某个子串」。
 * 把 `--no-deps` 从 `run` 之后挪到 `app` 之后，字符串里仍然"包含"它，文本断言照绿，
 * 但 compose 的实际语义已经变了。抽成纯函数后，位置与顺序都可以被精确断言。
 *
 * 同时钉两点防回归：
 *   ① deploy.js 不得再出现命令字面量（拼装只有 deployCommands.js 一处来源）；
 *   ② 备份连接串/镜像引用不得进入 argv（execFileSync 不解析 shell，但 argv 会出现在
 *      /proc/<pid>/cmdline，同机任意本地用户可读）。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const {
  composeArgs,
  buildPullInvocation,
  buildMigrateInvocation,
  buildUpInvocation,
  buildProbeInvocation,
  buildBackupInvocation,
  buildCommandPlan,
  formatInvocation,
} = require('../../../scripts/deployCommands');

const ROOT = path.resolve(__dirname, '../../..');
const DEPLOY_SCRIPT = path.join(ROOT, 'scripts', 'deploy.js');
const COMPOSE = '/srv/fsms/docker-compose.yml';

describe('compose 前缀', () => {
  test('-f 紧跟 compose，路径是单个 argv 元素（含空格也不被拆开）', () => {
    const withSpaces = '/srv/my project/docker-compose.yml';
    expect(composeArgs(withSpaces)).toEqual(['compose', '-f', withSpaces]);
  });
});

describe('迁移命令：status 与 up 共用同一前缀', () => {
  test('status 的完整 argv', () => {
    expect(buildMigrateInvocation('status', { composeFile: COMPOSE })).toEqual({
      file: 'docker',
      args: [
        'compose',
        '-f',
        COMPOSE,
        'run',
        '--rm',
        '--no-deps',
        'app',
        'node',
        'node_modules/.bin/migrate-mongo',
        'status',
      ],
    });
  });

  test('up 与 status 只差最后一个元素（防止一侧漏了 --rm/--no-deps）', () => {
    const status = buildMigrateInvocation('status', { composeFile: COMPOSE });
    const up = buildMigrateInvocation('up', { composeFile: COMPOSE });
    expect(up.args.slice(0, -1)).toEqual(status.args.slice(0, -1));
    expect(status.args.at(-1)).toBe('status');
    expect(up.args.at(-1)).toBe('up');
  });

  test('--no-deps 必须在 app 之前（挪到 app 之后会被当成要传给容器的参数）', () => {
    const { args } = buildMigrateInvocation('up', { composeFile: COMPOSE });
    expect(args.indexOf('--no-deps')).toBeLessThan(args.indexOf('app'));
    expect(args.filter((a) => a.endsWith('/migrate-mongo'))).toHaveLength(1);
  });
});

describe('拉取 / 切换 / 探针', () => {
  test('pull 只拉 app，不带 --build', () => {
    expect(buildPullInvocation({ composeFile: COMPOSE }).args).toEqual([
      'compose',
      '-f',
      COMPOSE,
      'pull',
      'app',
    ]);
  });

  test('切换用 --no-build：发布的是已拉取的镜像，不是现场构建', () => {
    expect(buildUpInvocation({ composeFile: COMPOSE }).args).toEqual([
      'compose',
      '-f',
      COMPOSE,
      'up',
      '-d',
      '--no-build',
      'app',
    ]);
  });

  test('探针打 /readyz（带 Mongo ping），URL 是最后一个元素', () => {
    const probe = buildProbeInvocation('http://127.0.0.1:3000/readyz');
    expect(probe.file).toBe('curl');
    expect(probe.args).toEqual([
      '--silent',
      '--output',
      '/dev/null',
      '--write-out',
      '%{http_code}',
      '--max-time',
      '5',
      'http://127.0.0.1:3000/readyz',
    ]);
    expect(probe.args.at(-1)).toMatch(/\/readyz$/);
  });
});

describe('备份命令与密钥边界', () => {
  test('bash + 脚本 + 备份目录，连接串只经 env 传递', () => {
    const backup = buildBackupInvocation({
      scriptFile: '/srv/fsms/scripts/backup-mongo.sh',
      backupDir: '/srv/backups',
    });
    expect(backup).toEqual({
      file: 'bash',
      args: ['/srv/fsms/scripts/backup-mongo.sh', '/srv/backups'],
    });
    expect(JSON.stringify(backup)).not.toMatch(/mongodb(\+srv)?:\/\//);
  });

  test('含分号/空格的目录仍是单个 argv 元素（execFileSync 不经过 shell）', () => {
    const hostile = '/srv/backups; rm -rf / #';
    const { args } = buildBackupInvocation({ backupDir: hostile });
    expect(args).toEqual([path.resolve(ROOT, 'scripts', 'backup-mongo.sh'), hostile]);
    expect(args.at(-1)).toBe(hostile);
  });
});

describe('命令计划：顺序与实发同源', () => {
  const plan = buildCommandPlan({
    composeFile: COMPOSE,
    probeUrl: 'http://127.0.0.1:3000/readyz',
  });

  test('步骤顺序：备份 → 拉取 → 迁移留痕 → 应用迁移 → 切换 → 健康门禁', () => {
    expect(plan.map((s) => s.id)).toEqual([
      'backup',
      'pull',
      'migrate-status',
      'migrate-up',
      'up',
      'health',
    ]);
  });

  test('顺序判据是下标关系（不依赖数组字面量恰好写对）', () => {
    const idx = (id) => plan.findIndex((s) => s.id === id);
    expect(idx('backup')).toBeLessThan(idx('migrate-up'));
    expect(idx('migrate-status')).toBeLessThan(idx('migrate-up'));
    expect(idx('migrate-up')).toBeLessThan(idx('up'));
    expect(idx('up')).toBeLessThan(idx('health'));
  });

  test('每步都是可执行的 {file, args[]}，没有字符串拼接形态', () => {
    for (const step of plan) {
      expect(typeof step.file).toBe('string');
      expect(Array.isArray(step.args)).toBe(true);
      expect(step.args.every((a) => typeof a === 'string')).toBe(true);
    }
    expect(formatInvocation(plan[0])).toBe(
      `bash ${path.resolve(ROOT, 'scripts', 'backup-mongo.sh')} ${path.resolve(ROOT, 'backups')}`
    );
  });
});

describe('deploy.js 只调用构造器，不再自带命令字面量', () => {
  const source = fs.readFileSync(DEPLOY_SCRIPT, 'utf8');

  test('引用了 deployCommands 模块', () => {
    expect(source).toContain("require('./deployCommands')");
  });

  test.each(['migrate-mongo', '--no-deps', 'node_modules/.bin', '--no-build'])(
    'deploy.js 中不再出现 %s 字面量',
    (literal) => {
      expect(source).not.toContain(literal);
    }
  );
});
