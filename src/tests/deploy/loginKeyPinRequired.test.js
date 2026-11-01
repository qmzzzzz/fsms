/**
 * 发布构建的前端公钥钉扎必须**强制**（2026-10-31，审计一-6）
 *
 * 缺陷形状（原实现）：`Compute login key pin` 步骤在 LOGIN_ECDH_PRIVATE_KEY 缺失时
 * 只写一条 `::warning::` 就继续，镜像照常构建、推送、部署。而运行期
 * （src/utils/loginCipher.js 的 verifyBuildPin）**只在** LOGIN_PUBLIC_KEY_SHA256_PIN
 * 非空时才比对——空值等于"跳过校验"。于是"前端包与运行私钥绑定"这条防线在这条
 * 路径上完全不存在：CI 全绿、镜像可拉可跑、没有任何一处会红。
 *
 * 本套件的两组判据互补，缺一组结论就不成立：
 *   ① 脚本行为：--require（或 REQUIRE_LOGIN_KEY_PIN=true）下缺输入必须非零退出；
 *      不强制时仍须输出空、退出 0（本地/PR 构建不能被误伤）。
 *   ② 接线：CI 的发布构建步骤必须真的带 --require、build-args 必须真的带
 *      REQUIRE_LOGIN_KEY_PIN=1、Dockerfile 必须真的有第二道闸。
 *      只测 ① 的话，把 --require 从 ci.yml 删掉不会有任何红——而失效形态
 *      （发布镜像不再钉扎）恰好就是这样悄悄回去的。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join(ROOT, 'scripts/login-key-pin.js');
const NODE = process.execPath;

const runScript = (args, env = {}) =>
  spawnSync(NODE, [SCRIPT, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 60000,
    env: { ...process.env, LOGIN_ECDH_PRIVATE_KEY: '', ...env },
  });

/** 生成一把一次性 EC 私钥（PEM），指纹由本用例独立算出，与脚本结果对账 */
const makeEcPem = () =>
  crypto
    .generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .privateKey.export({ type: 'pkcs8', format: 'pem' });

const fingerprintOf = (pem) => {
  const pub = crypto.createPublicKey(crypto.createPrivateKey(pem));
  return crypto
    .createHash('sha256')
    .update(pub.export({ type: 'spki', format: 'der' }))
    .digest('hex');
};

describe('第 1 组 · login-key-pin.js：强制档的行为', () => {
  test('缺输入 + --require ⇒ 非零退出并说明"拒绝产出未钉扎包"（不许静默放过）', () => {
    const r = runScript(['--require']);
    expect(r.status).not.toBe(0);
    expect(r.stdout.trim()).toBe('');
    expect(r.stderr).toContain('--require');
    expect(r.stderr).toContain('LOGIN_ECDH_PRIVATE_KEY');
  });

  test('缺输入 + REQUIRE_LOGIN_KEY_PIN=true（环境变量入口）⇒ 同样非零退出', () => {
    const r = runScript([], { REQUIRE_LOGIN_KEY_PIN: 'true' });
    expect(r.status).not.toBe(0);
    expect(r.stdout.trim()).toBe('');
  });

  test('缺输入且不强制 ⇒ 空输出 + 退出 0（本地开发与 PR 构建不得被误伤）', () => {
    const r = runScript([]);
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe('');
  });

  test('开关拼错（--requre）必须拒绝：手误绝不能降级成"这次不强制"', () => {
    const r = runScript(['--requre']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('--requre');
    expect(r.stderr).toContain('--require');
  });

  test('多于一个位置参数拒绝（PEM 路径只允许一个，避免把开关当路径读）', () => {
    const r = runScript(['a.pem', 'b.pem']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('一个 PEM 文件路径');
  });

  test('有输入时输出 64 位指纹且与独立计算等值（强制档不改变正常路径）', () => {
    const pem = makeEcPem();
    const r = runScript(['--require'], { LOGIN_ECDH_PRIVATE_KEY: pem });
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toBe(fingerprintOf(pem));
  });

  test('私钥无法解析 ⇒ 非零退出（不许把解析失败变成空指纹）', () => {
    const r = runScript(['--require'], { LOGIN_ECDH_PRIVATE_KEY: 'not-a-pem' });
    expect(r.status).not.toBe(0);
    expect(r.stdout.trim()).toBe('');
  });
});

describe('第 2 组 · 接线：发布构建路径上确实挂着这道强制', () => {
  const ci = fs.readFileSync(path.join(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const dockerfile = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');

  test('CI 里确实以 --require 调用该脚本', () => {
    expect(ci).toContain('node scripts/login-key-pin.js --require');
  });

  test('CI 发布构建向镜像传 REQUIRE_LOGIN_KEY_PIN=1（Dockerfile 第二道闸的开关）', () => {
    expect(ci).toContain('REQUIRE_LOGIN_KEY_PIN=1');
  });

  test('Dockerfile 有第二道闸：该开关为 1 且指纹为空时构建失败', () => {
    expect(dockerfile).toContain('REQUIRE_LOGIN_KEY_PIN');
    // 判据是两个条件的合取（开关为 1 且指纹为空）——缺任一条都等于没闸
    expect(
      dockerfile.includes('"1" ]') && dockerfile.includes('-z "$VITE_LOGIN_PUBLIC_KEY_SHA256"')
    ).toBe(true);
    // 闸门本体必须真的能失败：同一段 RUN 里要有 exit 1
    expect(/REQUIRE_LOGIN_KEY_PIN=[\s\S]{0,400}?exit 1/.test(dockerfile)).toBe(true);
  });

  test('未钉扎这条路在 CI 里已经不存在：warning 分支不得留下（它正是原来的失效形态）', () => {
    expect(ci).not.toContain('LOGIN_ECDH_PRIVATE_KEY 未配置——镜像不做登录公钥钉扎');
  });
});
