/**
 * PII 迁移/轮换脚本的主密钥判据（`scripts/migrate-pii-encryption.js`）
 *
 * 缺陷形态（2026-10-01 第 7 轮审计，探针实测）：脚本连库前只过 `piiCrypto.requireMasterSecret()`，
 * 而那一道拦的是**退化字面量**（`''`/`undefined`/`null`/`nan`）。实测同时通过它的还有：
 *   `AES_SECRET_KEY=abc`、`.env.example` 里的原文占位符 `<CHANGE_ME>`、40 个同一字符。
 * 于是 `--apply` 会把全表 `users.phone` 重加密到一把可穷举的密钥之下，而脚本照样打印
 * 「✅ 轮换完成」——改写不可逆，等下次启动 `validate.js` 才响已经晚了。
 * 同族的 `scripts/migrate-mfa-secret.js` 在改写数据前用的正是启动校验那把尺
 * （`validate.js` 的 `isWeakSecret`）：**同一个风险面，两条路径判据差一档**，
 * 而差的那一档只有数据损失。本用例把"两条路径同一把尺"钉住。
 *
 * 判据分工（缺一条就留有假绿空间）：
 *   1. 三种**不同成因**的弱值各一条：短（长度判据）、占位符（形态判据）、
 *      40 个同一字符（长度与黑名单都过得了，只有熵/周期判据能拦）——
 *      只钉第一条会放行一份"顺手加个 `length < 32`"的实现；
 *   2. 退化字面量仍走**第一道**（exit 1 而不是 exit 2）：新增判据不得把原有判据吞掉；
 *   3. 强密钥对照组必须**穿过**这道闸（现场是回退库名被拒，exit 2 但文案不同）：
 *      否则"永远拒绝"的实现也能让 1) 全绿；
 *   4. 前提自证：直接问 `isWeakSecret` 本人，四个期望值是人算出来的，
 *      不是从脚本输出反推的——判据哪天改动，这里先红，而不是让本文件跟着一起改期望。
 *
 * 全部子进程都在 `MONGODB_URI` 为空的环境里跑，因此在 `--apply` 的"回退库拒绝"分支
 * 就退出：既不会连库，更不会改写任何集合（探针实测过这条路径不产生连接）。
 */

const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join('scripts', 'migrate-pii-encryption.js');

// 夹具用 sha256 摘要而不是 randomBytes：64 位十六进制熵远高于门槛，且**逐次可重现**
// （随机值一旦哪天被判弱，本文件就成了偶发红）。它也不是一段可辨认的凭据。
const STRONG_FIXTURE = crypto.createHash('sha256').update('fsms-pii-gate-fixture').digest('hex');

const { isWeakSecret } = require('../../../src/config/validate');

/** 真跑子进程：判据在脚本的启动序列里，桩不进 main() 就测不到它 */
const run = (aesSecretKey) => {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, '--apply'], {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 60000,
      env: {
        ...process.env,
        AES_SECRET_KEY: aesSecretKey,
        // 必须显式清空：`src/tests/setup.js` 会给每个 worker 写入
        // AES_SECRET_KEY_FILE（指向测试副本），而子进程无条件继承父环境。
        // secrets.js 的 `<NAME>_FILE` 约定是"文件优先"⇒ 它会把这里传的弱值
        // **覆盖回测试强密钥**，四种弱值全部走到下一道闸（实测：不清空时
        // 4/6 用例红，收到的输出全是"回退库名被拒"）。判"传进去的密钥弱不弱"
        // 的用例，得先确认传进去的确实是那把密钥。
        AES_SECRET_KEY_FILE: '',
        MONGODB_URI: '',
        ALLOWED_SOURCE_DB: '',
        PII_ROTATION_OLD_AES_KEY: '',
        PII_ROTATION_CURRENT_KEY: '',
      },
    });
    return { code: 0, output: stdout };
  } catch (e) {
    return { code: e.status, output: `${e.stderr || ''}${e.stdout || ''}` };
  }
};

describe('migrate-pii-encryption：主密钥强度必须在改写之前判', () => {
  test('前提自证：isWeakSecret 对这四种输入的判断是人算出来的', () => {
    expect(isWeakSecret('abc')).toBe(true); // 长度
    expect(isWeakSecret('<CHANGE_ME>')).toBe(true); // 占位符形态
    expect(isWeakSecret('a'.repeat(40))).toBe(true); // 长度够、熵为 0
    expect(isWeakSecret(STRONG_FIXTURE)).toBe(false);
  });

  test('短弱值 abc ⇒ 拒绝改写（exit 2）', () => {
    const r = run('abc');
    expect(r.code).toBe(2);
    expect(r.output).toContain('强度校验');
  });

  test('.env.example 的原文占位符 <CHANGE_ME> ⇒ 拒绝改写', () => {
    const r = run('<CHANGE_ME>');
    expect(r.code).toBe(2);
    expect(r.output).toContain('强度校验');
  });

  test('40 个同一字符（长度达标）⇒ 仍拒绝：钉的是整把尺而不是一个长度检查', () => {
    const r = run('a'.repeat(40));
    expect(r.code).toBe(2);
    expect(r.output).toContain('强度校验');
  });

  test('退化字面量 undefined ⇒ 仍由第一道给出 exit 1（新判据不得吞掉旧判据）', () => {
    const r = run('undefined');
    expect(r.code).toBe(1);
    expect(r.output).toContain('未设置为有效值');
    expect(r.output).not.toContain('强度校验');
  });

  test('对照组：强随机密钥穿过本闸，停在"回退库名"那一道', () => {
    const r = run(STRONG_FIXTURE);
    expect(r.code).toBe(2);
    expect(r.output).not.toContain('强度校验');
    // 走到下一道闸的凭据：回退库拒绝的文案（同库判据见 scripts/destructiveGuard.js）
    expect(r.output).toContain('回退');
  });
});
