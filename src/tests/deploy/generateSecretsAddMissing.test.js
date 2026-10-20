/**
 * O-4：generate-secrets --add-missing（只补独立新密钥，不触发全量轮换）
 *
 * 背景：升级引入 redis_password 后，现有 secrets 目录缺这一个文件。旧脚本只接受
 * --force 整套重生成——JWT/AES/HMAC/DB 全部轮换意味着全体下线、MFA 密文不可解密、
 * 审计 HMAC 失效。--add-missing 必须做到：
 *   ① 只写缺失文件，已有文件一个字节都不动；
 *   ② mongodb_uri 由 mongo_root_password 派生，三件套不成套时拒绝（补谁都是错代次）；
 *   ③ 与 --force / --env-snippet / 无 --out 的组合在生成任何密钥前以退出码 2 拒绝。
 *
 * 全部用真实子进程跑脚本：参数解析与落盘顺序正是被测对象，mock 掉就测不到了。
 */

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts/generate-secrets.js');

const run = (args) =>
  spawnSync(process.execPath, [SCRIPT, ...args], { cwd: ROOT, encoding: 'utf8', timeout: 60000 });

const read = (dir, name) => fs.readFileSync(path.join(dir, name), 'utf8');

/**
 * 恢复继承 ACL。脚本按设计把目录收紧为「仅当前用户」；Windows 上该 ACE 由 icacls
 * 按本地代码页写入，含非 ASCII 用户名时当前进程反而读不了自己刚写的文件（环境缺陷，
 * 非脚本语义）。测试只在读/删之前解锁，不影响脚本自身的收紧与复核断言。
 */
const unlock = (dir) => {
  if (process.platform !== 'win32') return;
  spawnSync('icacls', [dir, '/reset', '/T', '/C'], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 60000,
  });
};

describe('O-4 generate-secrets --add-missing', () => {
  let dir;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gs-add-missing-'));
  });

  afterEach(() => {
    unlock(dir);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  /** 先用普通模式铺一套完整密钥，作为「现有部署」的起点 */
  const seedFullSet = () => {
    const r = run(['--out', dir]);
    expect(r.status).toBe(0);
    expect(fs.existsSync(path.join(dir, 'redis_password'))).toBe(true);
    unlock(dir);
  };

  test('只补 redis_password：其余密钥逐字节不变，退出 0', () => {
    seedFullSet();
    const untouched = ['jwt_secret', 'aes_secret_key', 'hmac_secret', 'mongodb_uri'];
    const before = Object.fromEntries(untouched.map((n) => [n, read(dir, n)]));
    const ecdhBefore = read(dir, 'login_ecdh_private_key');

    fs.rmSync(path.join(dir, 'redis_password'));
    const r = run(['--out', dir, '--add-missing']);
    unlock(dir);

    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    expect(r.stdout).toContain('仅补齐 1 个缺失文件');
    expect(r.stdout).toContain('redis_password');
    for (const name of untouched) expect(read(dir, name)).toBe(before[name]);
    expect(read(dir, 'login_ecdh_private_key')).toBe(ecdhBefore);
    expect(read(dir, 'redis_password').length).toBeGreaterThanOrEqual(16);
  });

  test('产物齐全时不做任何写入，退出 0', () => {
    seedFullSet();
    const before = fs.readdirSync(dir).sort();
    const jwt = read(dir, 'jwt_secret');

    const r = run(['--out', dir, '--add-missing']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('无需补齐');
    expect(fs.readdirSync(dir).sort()).toEqual(before);
    expect(read(dir, 'jwt_secret')).toBe(jwt);
  });

  test('Mongo 三件套部分缺失：拒绝补齐（uri 与 password 不能分属两代）', () => {
    seedFullSet();
    fs.rmSync(path.join(dir, 'mongo_root_password'));

    const r = run(['--out', dir, '--add-missing']);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Mongo 凭据三件套不成套');
    expect(r.stderr).toContain('mongodb_uri');
    // 拒绝必须发生在落盘之前：缺失文件没有被悄悄补上
    expect(fs.existsSync(path.join(dir, 'mongo_root_password'))).toBe(false);
  });

  test('空目录 + --add-missing：等价于整套生成（三件套全缺时允许一致生成）', () => {
    const r = run(['--out', dir, '--add-missing']);
    unlock(dir);
    expect(r.status).toBe(0);
    const names = fs.readdirSync(dir);
    expect(names).toContain('mongodb_uri');
    expect(names).toContain('mongo_root_password');
    expect(names).toContain('redis_password');
    const uri = read(dir, 'mongodb_uri');
    expect(uri).toContain(encodeURIComponent(read(dir, 'mongo_root_password')));
  });

  test.each([
    ['缺少 --out', ['--add-missing'], '必须与 --out'],
    ['与 --force 互斥', ['--out', 'PLACEHOLDER', '--add-missing', '--force'], '互斥'],
    ['与 --env-snippet 互斥', ['--out', 'PLACEHOLDER', '--add-missing', '--env-snippet'], '互斥'],
  ])('%s：退出码 2 且 stdout 没有任何密钥', (_label, args, needle) => {
    const resolved = args.map((a) => (a === 'PLACEHOLDER' ? dir : a));
    const r = run(resolved);
    expect(r.status).toBe(2);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain(needle);
    expect(r.stderr).not.toMatch(/jwt_secret=|BEGIN [A-Z ]*PRIVATE KEY/);
  });
});
