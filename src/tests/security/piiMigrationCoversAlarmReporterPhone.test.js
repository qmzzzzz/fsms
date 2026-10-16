/**
 * PII 迁移脚本覆盖 firealarms.reporter.phone（P1，2026-10-16）
 *
 * 为什么必须有这条**真跑库**的用例，而不是只测模型接线：
 * 迁移脚本与模型是**两条独立的写侧**，它们对同一列写出的密文必须能互相解开——
 * 即 AAD 的 `field` 字面量必须逐字一致（模型 models/FireAlarm.js 写
 * `field: 'reporter.phone'`，脚本 PII_TARGETS 写 `path: 'reporter.phone'`）。
 * 一旦不一致：脚本迁移出来的行、模型新写的行，各自只有自己能解，
 * 同一列里两套绑定并存 ⇒ 读侧随机成功/失败。而**两边各自的单元用例都会全绿**
 * （各自自洽），只有"脚本写、模型读"这条跨边界用例能钉住它。
 *
 * 可证伪对：同时放一行**明文**用户手机号，证明本用例跑的是脚本的真实扫描路径
 * （不是"firealarms 恰好没数据所以什么也没发生"），也顺带守住 users 腿没被
 * 2026-10-16 的泛化改造改坏。
 */

const path = require('path');
const mongoose = require('mongoose');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../..');
const SCRIPT = path.join('scripts', 'migrate-pii-encryption.js');

const LEGACY_ALARM_PHONE = '13500135000';
const LEGACY_USER_PHONE = '13600136001';

describe('migrate-pii-encryption：报警上报人电话列纳入迁移', () => {
  let FireAlarm;
  const stamp = `pmmig${String(Date.now()).slice(-8)}`;
  let legacyAlarmId;
  let legacyUserId;

  const childUri = () =>
    `mongodb://${mongoose.connection.host}:${mongoose.connection.port}/${mongoose.connection.name}`;

  const runMigrate = (extraArgs = []) => {
    try {
      const stdout = execFileSync(process.execPath, [SCRIPT, '--apply', '--yes', ...extraArgs], {
        cwd: ROOT,
        encoding: 'utf8',
        stdio: 'pipe',
        timeout: 60000,
        env: {
          ...process.env,
          MONGODB_URI: childUri(),
          ALLOWED_SOURCE_DB: mongoose.connection.name,
          // 必须显式清空：setup.js 给每个 worker 写了 AES_SECRET_KEY_FILE，
          // secrets.js 的 `<NAME>_FILE` 约定是"文件优先"，会把这里传的值覆盖掉。
          // 本用例断言的是"脚本用这把钥加密、模型用同一把钥能解开"，得先确认
          // 子进程用的确实是同一把钥。
          AES_SECRET_KEY_FILE: '',
          PII_ROTATION_OLD_AES_KEY: '',
        },
      });
      return { code: 0, output: stdout };
    } catch (e) {
      return { code: e.status, output: `${e.stderr || ''}${e.stdout || ''}` };
    }
  };

  beforeAll(async () => {
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
    FireAlarm = require('../../models/FireAlarm');

    // 绕过文档中间件直写明文，模拟加密上线前的存量行
    legacyAlarmId = new mongoose.Types.ObjectId();
    await mongoose.connection.collection('firealarms').insertOne({
      _id: legacyAlarmId,
      alarmCode: `${stamp}-legacy`,
      alarmType: 'smoke',
      description: `${stamp} 存量报警`,
      reporter: { name: '存量上报人', phone: LEGACY_ALARM_PHONE },
      occurredAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    legacyUserId = new mongoose.Types.ObjectId();
    await mongoose.connection.collection('users').insertOne({
      _id: legacyUserId,
      username: `legacy_${stamp}`,
      email: `legacy-${stamp}@example.com`,
      password: 'x'.repeat(60),
      phone: LEGACY_USER_PHONE,
      status: 'active',
      roles: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection
        .collection('firealarms')
        .deleteMany({ description: new RegExp(stamp) })
        .catch(() => {});
      await mongoose.connection
        .collection('users')
        .deleteMany({ username: new RegExp(`^legacy_${stamp}$`) })
        .catch(() => {});
      await mongoose.connection.close();
    }
  });

  test('--apply 后两列都变成 enc.v2.，且**模型能解开脚本写出的密文**（AAD field 逐字一致）', async () => {
    const r = runMigrate();
    expect(r.code).toBe(0);
    expect(r.output).toContain('"firealarms"');
    expect(r.output).toContain('"corruptTotal": 0');

    const rawAlarm = await mongoose.connection
      .collection('firealarms')
      .findOne({ _id: legacyAlarmId });
    expect(rawAlarm.reporter.phone).toMatch(/^enc\.v2\./);
    expect(rawAlarm.reporter.phone).not.toContain(LEGACY_ALARM_PHONE);

    // 跨边界证据：模型 getter 解出明文 ⇒ 脚本的 AAD field 与模型写侧一致
    const alarm = await FireAlarm.findById(legacyAlarmId);
    expect(alarm.reporter.phone).toBe(LEGACY_ALARM_PHONE);

    // users 腿未被泛化改造改坏：密文 + 检索键同步
    const rawUser = await mongoose.connection.collection('users').findOne({ _id: legacyUserId });
    expect(rawUser.phone).toMatch(/^enc\.v2\./);
    expect(rawUser.phoneKey).toMatch(/^[0-9a-f]{64}$/);
  });

  test('幂等：再跑一次是演练形态的"无待迁移行"（v2 行被跳过，不会被重加密）', async () => {
    const r = runMigrate();
    expect(r.code).toBe(0);
    // 第二次跑时 firealarms 段应为 encryptedRows ≥ 1 而 plaintextRows = 0
    expect(r.output).toMatch(/"firealarms":\s*\{[^}]*"plaintextRows": 0/);

    const rawAlarm = await mongoose.connection
      .collection('firealarms')
      .findOne({ _id: legacyAlarmId });
    expect(rawAlarm.reporter.phone).toMatch(/^enc\.v2\./);
  });
});
