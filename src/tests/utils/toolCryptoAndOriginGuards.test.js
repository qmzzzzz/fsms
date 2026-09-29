/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：工具/密码学边界行为 + protocolCompliance / originCheck / securityRoutes
 * 守护的不变式：脱敏结果、解码抛错、口令接受与否、来源校验必须与实现一致（含注释所描述的行为）
 * 可证伪性：变异实测（筛查 N=2）：杀 6/9（3 个模块）
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [仍有效] `:173-176 / :1049-1108` 共 48 行**源码/注释文本正则断言**——文案同义改写即红、被搬进永不执行的分支即绿（deliverables/七维代码健康度深度审计-2026-09-18.md）
 *
 * 命名沿革：2026-09-20 由 `toolCryptoHardening.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 批次F 工具/密码学类修复回归（P3-26 ~ P3-36）
 *
 * 这批缺陷集中在「工具函数的边界行为」与「注释/配置与实现背离」两类。
 * 前者能直接断言（脱敏结果、解码是否抛错、口令是否被接受），
 * 后者只能锁定「实现侧的不变量」——注释本身无法测试，但注释所描述的行为可以。
 */

const fs = require('fs');
const path = require('path');
const request = require('supertest');

describe('批次F 工具与密码学加固回归', () => {
  // T-1：P3-30 用例会打开 Mongo 连接，套件结束必须关闭，
  // 否则遗留连接拖住 jest worker 优雅退出
  afterAll(async () => {
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close();
    }
  });

  // ================= P3-26 TOTP =================
  describe('P3-26 TOTP 常量时间比较与 Base32 严格解码', () => {
    const { verifyTotp, generateSecret, base32Decode, hotp } = require('../../utils/totp');
    /** 生成指定时间窗的 6 位码（totp.js 未导出按 counter 生成的入口，此处组合） */
    const codeAt = (secret, counter) => hotp(base32Decode(secret), counter);
    const currentCounter = () => Math.floor(Date.now() / 1000 / 30);

    test('Base32 含非法字符时抛错，不再与合法前缀解成同一密钥', () => {
      // 原实现 `if (idx === -1) continue` 会让下面两个输入产出相同密钥，
      // 结果是「录错密钥的用户能正常通过校验」，错误被推迟到无从排查的时点
      const good = 'JBSWY3DPEHPK3PXP';
      expect(() => base32Decode(`${good}!!!!`)).toThrow(/Base32/);
      expect(() => base32Decode(`${good}$%^`)).toThrow(/Base32/);
      // 且非法输入不会与合法前缀解出同一密钥
      expect(base32Decode(good).toString('hex')).toBeTruthy();
    });

    test('容忍的仅是格式性字符（填充/空白/连字符）', () => {
      const secret = generateSecret();
      const expected = base32Decode(secret).toString('hex');
      // 分组显示（每 4 位加空格/连字符）是认证器 App 的常见展示形式，须可直接粘贴
      const spaced = secret.replace(/(.{4})/g, '$1 ').trim();
      const dashed = secret.replace(/(.{4})/g, '$1-').replace(/-$/, '');
      expect(base32Decode(spaced).toString('hex')).toBe(expected);
      expect(base32Decode(dashed).toString('hex')).toBe(expected);
      expect(base32Decode(`${secret}====`).toString('hex')).toBe(expected);
    });

    test('多窗口校验遍历完整窗口后才返回（命中即 return 会泄露窗口位置）', () => {
      // 【本次改动改造：结构断言 → 行为断言】原用例断言源码里 `for (let i = -window`
      // 到 `return matchedCounter` 之间不含 return——把循环体改成命中即
      // `return { valid: true, counter: counter + i }` 后本用例仍绿（该 return
      // 位于切片区间之外）。现改为直接观测**比较次数**：常量时间要求
      // 无论命中哪个窗口，都必须把 2*window+1 个窗口全部比完。
      // 用 crypto.timingSafeEqual 的调用次数作为可观测代理（每次比较恰调用一次）。
      const crypto = require('crypto');
      const spy = jest.spyOn(crypto, 'timingSafeEqual');
      try {
        const secret = generateSecret();
        const counter = currentCounter();
        const window = 2;
        const expectedCalls = 2 * window + 1;

        // 命中第 1 个窗口（最早）：若命中即 return，调用次数会 < expectedCalls
        spy.mockClear();
        expect(verifyTotp(secret, codeAt(secret, counter - window), window)).toBe(true);
        const callsAtFirst = spy.mock.calls.length;
        expect(callsAtFirst).toBe(expectedCalls);

        // 命中最后一个窗口：调用次数必须与命中第一个窗口完全一致
        spy.mockClear();
        expect(verifyTotp(secret, codeAt(secret, counter + window), window)).toBe(true);
        const callsAtLast = spy.mock.calls.length;
        expect(callsAtLast).toBe(expectedCalls);

        // 全部未命中：同样遍历完整窗口
        spy.mockClear();
        expect(verifyTotp(secret, '000000', window)).toBe(false);
        expect(spy.mock.calls.length).toBe(expectedCalls);

        // 窗口内任意偏移都能通过（功能面）
        for (const offset of [-2, -1, 0, 1, 2]) {
          expect(verifyTotp(secret, codeAt(secret, counter + offset), window)).toBe(true);
        }
      } finally {
        spy.mockRestore();
      }
    });

    test('窗口外的验证码被拒绝', () => {
      const secret = generateSecret();
      expect(verifyTotp(secret, codeAt(secret, currentCounter() + 10), 1)).toBe(false);
    });
  });

  // ================= P3-27 maskIP / CBC =================
  describe('P3-27 IP 脱敏与遗留 CBC 解密', () => {
    const { DataMasking, aesCipher } = require('../../utils/encryption');

    test('IPv6 压缩写法先展开再取前 3 组（不再把接口标识当前缀）', () => {
      // 原实现「过滤空组后取前 3 个」会把 2001:db8::1 输出成 2001:db8:1:****，
      // 即把末尾的接口标识 1 冒充成前缀第三组 —— 脱敏结果与真实网段不符，
      // 按脱敏 IP 做溯源会指向错误网段
      expect(DataMasking.maskIP('2001:db8::1')).toBe('2001:db8:0:****');
      expect(DataMasking.maskIP('2001:db8:85a3::8a2e:370:7334')).toBe('2001:db8:85a3:****');
      expect(DataMasking.maskIP('::1')).toBe('0:0:0:****');
    });

    test('IPv4-mapped 地址按 IPv4 口径脱敏', () => {
      expect(DataMasking.maskIP('::ffff:192.168.1.100')).toBe('192.168.*.*');
    });

    test('无法解析的 IPv6 返回 ****，不做猜测式脱敏', () => {
      expect(DataMasking.maskIP('2001:db8::1::2')).toBe('****');
      expect(DataMasking.maskIP(':::')).toBe('****');
    });

    test('IPv4 保留前两段', () => {
      expect(DataMasking.maskIP('10.20.30.40')).toBe('10.20.*.*');
    });

    test('遗留 CBC 密文默认拒绝解密（填充预言机面收口）', () => {
      const saved = process.env.ALLOW_LEGACY_CBC_DECRYPT;
      delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
      try {
        // 构造一段「看起来像旧格式」的输入即可——重点是在解密之前就被拒绝
        const legacyLike = `${'0'.repeat(32)}:${Buffer.from('x').toString('base64')}`;
        expect(() => aesCipher.decrypt(legacyLike)).toThrow(/CBC/);
      } finally {
        if (saved === undefined) delete process.env.ALLOW_LEGACY_CBC_DECRYPT;
        else process.env.ALLOW_LEGACY_CBC_DECRYPT = saved;
      }
    });

    test('GCM 往返正常，不受上述收口影响', () => {
      const text = '消防设备编号-A0231';
      expect(aesCipher.decrypt(aesCipher.encrypt(text))).toBe(text);
    });
  });

  // ================= P3-28 ipRange =================
  describe('P3-28 ipRange 通配语法口径与文档一致', () => {
    const { validateRules, isIPAllowed } = require('../../utils/ipRange');

    test('三段简写被判为非法片段（配置者立刻可见，不静默失效）', () => {
      const result = validateRules('192.168.*');
      expect(result.valid).toBe(false);
      expect(result.invalid).toContain('192.168.*');
    });

    test('文件头声明的语法逐条可用（注释与实现对齐）', () => {
      for (const rule of [
        '192.168.1.1',
        '192.168.1.1-254',
        '192.168.1.0/24',
        '192.168.1.*',
        '192.168.1-10.*',
        '!192.168.1.1',
        '*',
      ]) {
        expect(validateRules(rule)).toMatchObject({ valid: true });
      }
    });

    test('等价的四段写法可表达同一意图', () => {
      expect(validateRules('192.168.*.*')).toMatchObject({ valid: true });
      expect(isIPAllowed('192.168.7.9', '192.168.*.*').allowed).toBe(true);
      expect(isIPAllowed('10.0.0.1', '192.168.*.*').allowed).toBe(false);
    });

    test('文件头注释显式说明四段约束（防止注释再次漂移）', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../utils/ipRange.js'), 'utf8');
      expect(source).toMatch(/须写满四段/);
    });
  });

  // ================= P3-29 密码策略 =================
  describe('P3-29 密码字符集、长度上限与双向隔离符', () => {
    const {
      validatePasswordStrength,
      stripControlChars,
      PASSWORD_MAX_BYTES,
      PASSWORD_MAX_LENGTH,
    } = require('../../utils/helpers');

    test('此前被误拒的强口令现在被接受', () => {
      // 这些符号都不在原白名单 [!@#$%^&*(),.?":{}|<>] 内
      for (const pwd of [
        'Str0ng-Pass2026',
        'Str0ng_Pass2026',
        'Str0ng=Pass2026',
        'Str0ng+Pass2026',
        'Str0ng[Pass]2026',
        "Str0ng'Pass2026",
        'Str0ng\\Pass2026',
        'Str0ng~Pass2026',
        'Str0ng`Pass2026',
        'Str0ng;Pass2026',
      ]) {
        expect(validatePasswordStrength(pwd)).toBeNull();
      }
    });

    test('无特殊字符仍被拒绝（放宽字符集不等于放宽规则）', () => {
      expect(validatePasswordStrength('Str0ngPass2026')).toMatch(/特殊字符/);
    });

    test('超过字符上限被拒绝（bcrypt 72 字节截断 → 等价口令绕过）', () => {
      const long = `Aa1!${'x'.repeat(PASSWORD_MAX_LENGTH)}`;
      expect(validatePasswordStrength(long)).toMatch(/超过/);
    });

    test('字符数合规但 UTF-8 字节数超限同样被拒绝', () => {
      // 中文单字符 3 字节：30 个汉字 = 90 字节 > 72，而 length 仅 34
      const pwd = `Aa1!${'消'.repeat(30)}`;
      expect(pwd.length).toBeLessThanOrEqual(PASSWORD_MAX_LENGTH);
      expect(Buffer.byteLength(pwd, 'utf8')).toBeGreaterThan(PASSWORD_MAX_BYTES);
      expect(validatePasswordStrength(pwd)).toMatch(/字节/);
    });

    test('双向隔离符 U+2066-U+2069 被清洗（Trojan Source 式显示篡改）', () => {
      for (const ch of ['\u2066', '\u2067', '\u2068', '\u2069']) {
        const cleaned = stripControlChars(`admin${ch}root`);
        expect(cleaned).not.toContain(ch);
      }
    });

    test('原有的双向控制符与控制字符清洗未退化', () => {
      expect(stripControlChars('a\u202Eb')).not.toContain('\u202E');
      expect(stripControlChars('a\nb')).not.toContain('\n');
    });

    test('User.password 有 maxlength 兜底（绕过路由直操模型时）', () => {
      const User = require('../../models/User');
      const opts = User.schema.path('password').options;
      expect(opts.maxlength[0]).toBe(PASSWORD_MAX_BYTES);
    });

    test('securityRoutes 改密路由的校验链委托单一强度实现（真实驱动路由校验器）', async () => {
      // 【本次改动改造：静态断言 → 行为断言】原用例只查源码里有没有
      // 'validatePasswordStrength' 字样——把该 custom 校验器整段删掉，
      // 断言仍绿（字样还在别处/注释里也可能命中）。
      // 现改为取出 router 上 /change-password 的真实校验中间件链并驱动它：
      // 强口令放行、无特殊字符被拒、两次不一致被拒——三条都来自真实执行。
      const router = require('../../routes/securityRoutes');
      const layer = router.stack.find((l) => l.route && l.route.path === '/change-password');
      expect(layer).toBeTruthy();
      // 挂载顺序：authenticate → passwordChangeLimiter → express-validator 链 → 控制器。
      // 本用例只驱动校验器（认证/限流由各自套件覆盖）：express-validator 的
      // middleware 携带 builderOrContext/run 特征键，据此精确识别。
      const validators = layer.route.stack
        .map((s) => s.handle)
        .filter((h) => h && h.builderOrContext !== undefined && typeof h.run === 'function');
      // 防「过滤过度导致空链」的假绿：change-password 的校验器数组必有多个条目
      expect(validators.length).toBeGreaterThanOrEqual(4);

      const { validationResult } = require('express-validator');
      const runChain = async (body) => {
        const req = {
          body,
          headers: {},
          method: 'PUT',
          originalUrl: '/api/security/change-password',
          // 校验器链内的 custom(rejectPlaintextInStrict) 只读 config；
          // 其余自定义校验读 req.body，均不需要 req.user
          app: { get: () => undefined },
        };
        const res = {
          statusCode: null,
          body: null,
          headers: {},
          setHeader(name, value) {
            this.headers[name] = value;
            return this;
          },
          getHeader(name) {
            return this.headers[name];
          },
          status(code) {
            this.statusCode = code;
            return this;
          },
          json(payload) {
            this.body = payload;
            return this;
          },
          send(payload) {
            this.body = payload;
            return this;
          },
        };
        for (const h of validators) {
          let advanced = false;
          let thrown = null;
          const next = (e) => {
            advanced = true;
            if (e) thrown = e;
          };
          const ret = h(req, res, next);
          if (ret && typeof ret.then === 'function') await ret;
          if (thrown) throw thrown;
          if (!advanced) return { rejected: true, status: res.statusCode, body: res.body };
        }
        // express-validator 的校验失败不直接响应，而是把错误累积到 req 上，
        // 由消费方（控制器/consumeValidation）读取。此处按同一口径判定。
        const errors = validationResult(req);
        return { rejected: !errors.isEmpty(), errors: errors.array().map((e) => e.msg) };
      };

      // 强口令（含旧白名单外的连字符）必须通过——口径与 helpers 单一实现一致
      await expect(
        runChain({
          currentPassword: 'Old1!aaaa',
          newPassword: 'Str0ng-Pass2026',
          confirmPassword: 'Str0ng-Pass2026',
        })
      ).resolves.toEqual({ rejected: false, errors: [] });

      // 无特殊字符：必须被拒（若 routes 复刻旧正则或删除校验器，这里会漏过）
      const weak = await runChain({
        currentPassword: 'Old1!aaaa',
        newPassword: 'Str0ngPass2026',
        confirmPassword: 'Str0ngPass2026',
      });
      expect(weak.rejected).toBe(true);
      // 错误文案必须来自 helpers 的单一实现（含「特殊字符」字样），
      // 若 routes 复刻旧正则或删掉校验器，这里同时失守
      expect(weak.errors.join(' | ')).toMatch(/特殊字符/);

      // 两次输入不一致：必须被拒
      const mismatch = await runChain({
        currentPassword: 'Old1!aaaa',
        newPassword: 'Str0ng-Pass2026',
        confirmPassword: 'Other1!aaaa',
      });
      expect(mismatch.rejected).toBe(true);
      expect(mismatch.errors.join(' | ')).toMatch(/两次输入的密码不一致/);
    });
  });

  // ================= P3-30 username 大小写 =================
  describe('P3-30 username 唯一索引大小写不敏感', () => {
    const User = require('../../models/User');

    test('username 字段不再声明字段级 unique（会生成默认 collation 索引）', () => {
      expect(User.schema.path('username').options.unique).toBeUndefined();
    });

    test('存在带 collation 的 username 唯一索引', () => {
      const idx = User.schema.indexes().find(([key]) => key.username === 1);
      expect(idx).toBeDefined();
      const [, opts] = idx;
      expect(opts.unique).toBe(true);
      expect(opts.collation).toMatchObject({ strength: 2 });
      expect(opts.name).toBe('username_ci');
    });

    test('findByUsername 带同一 collation（否则查不到且退化为全表扫描）', () => {
      const q = User.findByUsername('AdMiN');
      expect(q.getOptions().collation).toMatchObject({ strength: 2 });
      q.catch(() => {}); // 不实际执行
    });

    /**
     * 【顺序无关修复】建立本 describe 的基准数据，幂等：确保内存库已连接、
     * 索引已同步到 schema 定义（库里可能残留字段级 unique 生成的 username_1），
     * 且存在一条 username='CaseTester' 的账户。
     *
     * 背景：`findByUsername` 用例此前**隐式**依赖上一条用例先跑——只有它建立连接
     * 并创建 CaseTester。随机顺序下 findByUsername 先跑时连接尚未建立、账户也不存在
     * → `users.findOne() buffering timed out after 10000ms`（seed=42 实测）。
     * 造数改为幂等复用（重复插入会撞 email 唯一索引，不能无脑 create）。
     */
    const ensureCaseTester = async () => {
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      // 内存库里此前可能残留字段级 unique 生成的 username_1，先同步到 schema 定义
      await User.syncIndexes();
      const base = { password: 'Qz7#Lm42vTx9', realName: '大小写测试' };
      const existing = await User.findOne({ email: 'case1@example.com' });
      if (!existing) {
        await User.create({ ...base, username: 'CaseTester', email: 'case1@example.com' });
      }
      return base;
    };

    test('大小写不同的用户名被唯一索引拒绝', async () => {
      const base = await ensureCaseTester();
      await expect(
        User.create({ ...base, username: 'casetester', email: 'case2@example.com' })
      ).rejects.toMatchObject({ code: 11000 });
    });

    test('findByUsername 可用任意大小写命中同一账户', async () => {
      await ensureCaseTester();
      const found = await User.findByUsername('CASETESTER');
      expect(found).not.toBeNull();
      expect(found.username).toBe('CaseTester');
    });

    test('索引对账在存在大小写冲突时保留旧索引而非删除（不出现零约束窗口）', async () => {
      // 【本次改动改造：静态断言 → 行为断言】原用例比较源码里 `$toLower` 与
      // `dropIndex('username_1')` 的字符位置——把冲突分支改成 `if (false)` 时
      // 两处文本仍在，断言照样绿。现改为真实构造「升级前的库」：
      // 只留 legacy username_1 + 两个大小写冲突账号，调 reconcileUserIndexes，
      // 断言旧索引被保留（先删后建若失败则两个约束都没有）。
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      const { reconcileUserIndexes } = require('../../services/initData');
      await mongoose.connection.dropCollection('users').catch(() => {});
      const coll = mongoose.connection.collection('users');
      await coll.createIndex({ username: 1 }, { unique: true, name: 'username_1' });
      await coll.createIndex({ email: 1 }, { unique: true, name: 'email_1' });
      const names0 = (await coll.indexes()).map((i) => i.name);
      if (names0.includes('username_ci')) await coll.dropIndex('username_ci');

      await coll.insertOne({ username: 'AdminZ', email: 'p330a@example.com', password: 'x' });
      await coll.insertOne({ username: 'adminz', email: 'p330b@example.com', password: 'x' });

      await reconcileUserIndexes();

      const names = (await coll.indexes()).map((i) => i.name);
      expect(names).toContain('username_1'); // 承重点：不得先删
      expect(names).toContain('email_1');
      // 收尾：恢复 schema 定义的索引形态，避免影响同 worker 的后续用例
      await coll.dropCollection?.();
      await mongoose.connection.dropCollection('users').catch(() => {});
      await User.syncIndexes();
    });
  });

  // ================= P3-31 logShipper =================
  describe('P3-31 日志转发行序与缓冲断档标记', () => {
    const { HttpShipperTransport, BUFFER_CAP } = require('../../utils/logShipper');

    /** 构造一个受控的 transport：_post 由测试决定成功/失败与耗时 */
    const makeTransport = (postImpl) => {
      const t = new HttpShipperTransport({
        url: 'http://127.0.0.1:1/ingest',
        batchSize: 5,
        intervalMs: 3600000,
      });
      t._post = postImpl;
      return t;
    };

    afterEach(() => jest.useRealTimers());

    test('在途 flush 期间的并发 flush 直接返回（行序不被打乱）', async () => {
      const sent = [];
      let release;
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      const t = makeTransport(async (batch) => {
        await gate;
        sent.push([...batch]);
      });

      for (let i = 0; i < 5; i++) t.log(`line-${i}`, () => {});
      // 首个 flush 已由满额触发并卡在 gate 上
      const concurrent = t._flush();
      // 并发调用不得再取走一批
      expect(t.buffer.length).toBe(0);
      release();
      await concurrent;
      await new Promise((r) => setImmediate(r));
      expect(sent.length).toBe(1);
      await t.close();
    });

    test('发送失败的批次回到缓冲头部，重发时顺序与产生顺序一致', async () => {
      const attempts = [];
      let failFirst = true;
      const t = makeTransport(async (batch) => {
        attempts.push([...batch]);
        if (failFirst) {
          failFirst = false;
          throw new Error('network down');
        }
      });

      for (let i = 0; i < 5; i++) t.log(`old-${i}`, () => {});
      await new Promise((r) => setImmediate(r));
      // 失败期间又来了新行
      for (let i = 0; i < 3; i++) t.log(`new-${i}`, () => {});
      await t._flush();

      expect(attempts.length).toBe(2);
      // 第二次发送必须还是那批旧行，而不是被新行插队
      expect(attempts[1][0]).toContain('old-0');
      await t.close();
    });

    test('缓冲超限时写入可检索的断档标记（丢失不再静默）', () => {
      const t = makeTransport(async () => {});
      t.batchSize = BUFFER_CAP + 100; // 避免中途触发 flush
      for (let i = 0; i < BUFFER_CAP + 50; i++) {
        t.buffer.push(`filler-${i}`);
      }
      t._trimToCap();

      expect(t.buffer.length).toBe(BUFFER_CAP);
      const head = JSON.parse(t.buffer[0]);
      expect(head.__log_shipper_gap__).toBeGreaterThan(0);
      expect(head.message).toMatch(/丢弃最旧/);
    });

    test('close 会等待在途批次结束后再排空（关停时的行不被丢弃）', async () => {
      const sent = [];
      const t = makeTransport(async (batch) => {
        await new Promise((r) => setTimeout(r, 30));
        sent.push([...batch]);
      });
      for (let i = 0; i < 5; i++) t.log(`bye-${i}`, () => {});
      t.log('last-line', () => {});
      await t.close();
      // 两批都应送出：满额那批 + close 时剩余的那批
      expect(sent.length).toBe(2);
      expect(sent[1]).toContain('last-line');
    });
  });

  // ================= P3-32 日志取证与 query 脱敏 =================
  describe('P3-32 进程级异常落盘与访问日志 query 脱敏', () => {
    const { redactUrlQuery, SENSITIVE_QUERY_KEYS } = require('../../utils/helpers');

    test('敏感 query 值被打码，键名与结构保留', () => {
      expect(redactUrlQuery('/api/x?token=abc123&page=2')).toBe('/api/x?token=***&page=2');
      expect(redactUrlQuery('/api/x?refresh_token=zzz&Password=p')).toBe(
        '/api/x?refresh_token=***&Password=***'
      );
    });

    test('无 query 或无敏感键时原样返回', () => {
      expect(redactUrlQuery('/api/users')).toBe('/api/users');
      expect(redactUrlQuery('/api/users?page=1&limit=10')).toBe('/api/users?page=1&limit=10');
    });

    test('非字符串输入不抛错', () => {
      expect(redactUrlQuery(undefined)).toBeUndefined();
      expect(redactUrlQuery(null)).toBeNull();
    });

    test('敏感键清单覆盖凭据类参数', () => {
      for (const k of ['token', 'password', 'secret', 'signature', 'otp']) {
        expect(SENSITIVE_QUERY_KEYS).toContain(k);
      }
    });

    test('访问日志真实输出脱敏后的 URL（morgan 走 safe-url 而非裸 originalUrl）', async () => {
      // 【本次改动改造：静态断言 → 行为断言】原用例只断言 app.js 源码里出现
      // 'safe-url' 字符串——实测把 token 处理器换成 `req.originalUrl` 后仍然全绿
      // （源码里仍有 'safe-url' 这个名字）。改为真实发起带敏感 query 的请求，
      // 捕获 morgan 写入 logger.info 的访问日志行，断言明文令牌不出现。
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      require('../../models/TokenBlacklist');
      const { createApp } = require('../../app');
      const logger = require('../../utils/logger');
      const spy = jest.spyOn(logger, 'info').mockImplementation(() => {});
      try {
        const app = createApp();
        const res = await request(app).get('/api?token=SUPERSECRET_MARKER&page=2');
        expect(res.status).toBe(200);
        const lines = spy.mock.calls.map((c) => String(c[0])).filter((l) => l.includes('GET /api'));
        expect(lines.length).toBeGreaterThan(0);
        const joined = lines.join('\n');
        // 正反两面：明文不得出现；打码标记必须出现（防「整行被丢弃」式假绿）
        expect(joined).not.toContain('SUPERSECRET_MARKER');
        expect(joined).toContain('token=***');
      } finally {
        spy.mockRestore();
      }
    });

    test('生产模式下 logger 注册 exception/rejection 处理器且不抢占退出', () => {
      // 【本次改动改造：静态断言 → 行为断言】原用例匹配 logger.js 源码里的
      // 'exceptionHandlers'/'exitOnError: false' 字面量——实测把第 125 行的
      // exitOnError 改成 true 后仍全绿（第 92 行注释里同样含该字符串，
      // 正则命中注释）。改为在真实生产模式下 require logger 并读取实例状态：
      // winston 配置 exceptionHandlers 后会向 logger.transports 追加
      // ExceptionStream/RejectionStream，可直接观测；exitOnError 亦可读。
      const { execFileSync } = require('child_process');
      const ROOT = path.join(__dirname, '..', '..', '..');
      const script = `
        const l = require(process.env.PROBE_ROOT + '/src/utils/logger');
        const names = l.transports.map((t) => t.constructor.name);
        process.stdout.write('R:' + JSON.stringify({
          exitOnError: l.exitOnError,
          names,
          excKeys: l.exceptions ? Object.keys(l.exceptions) : null,
          rejKeys: l.rejections ? Object.keys(l.rejections) : null,
        }));
      `;
      const run = (nodeEnv) => {
        const out = execFileSync(process.execPath, ['-e', script], {
          cwd: ROOT,
          env: { ...process.env, NODE_ENV: nodeEnv, PROBE_ROOT: ROOT },
          encoding: 'utf8',
          stdio: 'pipe',
        });
        return JSON.parse(out.match(/R:\{.*\}/)[0].slice(2));
      };

      const prod = run('production');
      // 不抢占退出：exitOnError 必须为 false（true 会抢在 index.js 审计 flush 前退出）
      expect(prod.exitOnError).toBe(false);
      // 崩溃取证 transport 真实存在（winston 配置 exceptionHandlers 的产物）
      expect(prod.names).toEqual(expect.arrayContaining(['ExceptionStream', 'RejectionStream']));
      expect(prod.excKeys).toEqual(expect.arrayContaining(['logger', 'handlers']));
      expect(prod.rejKeys).toEqual(expect.arrayContaining(['logger', 'handlers']));

      // 对照：测试环境刻意不挂载（避免 jest.resetModules 反复追加 process 监听器）
      const test = run('test');
      expect(test.exitOnError).toBe(false);
      expect(test.names).not.toEqual(expect.arrayContaining(['ExceptionStream']));
    });
  });

  // ================= P3-34 errorHandler 防御 =================
  describe('P3-34 重复键错误处理器自身的防御', () => {
    const errorHandler = require('../../middleware/errorHandler');

    const buildRes = () => {
      const res = {
        statusCode: 200,
        payload: null,
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(payload) {
          this.payload = payload;
          return this;
        },
      };
      return res;
    };
    const req = { method: 'POST', originalUrl: '/api/users' };

    test('11000 缺少 keyPattern 时仍返回 400，而非把错误处理器自己打成 500', () => {
      const res = buildRes();
      // 驱动在批量写/序列化传递等场景只给 errmsg
      errorHandler({ code: 11000, errmsg: 'E11000 duplicate key' }, req, res, () => {});
      expect(res.statusCode).toBe(400);
      expect(res.payload.message).toBe('资源已存在');
    });

    test('keyPattern 存在时行为不变', () => {
      // 「行为不变」的实质内容有二：① 字段名仍从 keyPattern 的键提取并进 warn；
      // ② 对外响应体保持通用文案「资源已存在」，不把索引/字段名泄露给客户端。
      // 只断 400 时，字段名提取被掏空、或响应体改成回显字段名都看不出来。
      // 【未覆盖，如实标注】`err.keyPattern || err.keyValue` 的优先级顺序本用例
      // 未构造「两者同时存在」的输入，故该顺序本身不可证伪（驱动输出的两者
      // 键名同源，此处不额外造不可达状态去凑）。
      const logger = require('../../utils/logger');
      const spy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      try {
        const res = buildRes();
        errorHandler({ code: 11000, keyPattern: { username: 1 } }, req, res, () => {});
        expect(res.statusCode).toBe(400);
        expect(res.payload).toEqual({ success: false, message: '资源已存在', errors: null });
        // 实测日志文案：'DuplicateKeyError: username'（字段名取自 keyPattern 的键）
        expect(spy).toHaveBeenCalledWith('DuplicateKeyError: username');
      } finally {
        spy.mockRestore();
      }
    });

    test('仅有 keyValue 时也能取到字段名', () => {
      const res = buildRes();
      errorHandler({ code: 11000, keyValue: { email: 'a@b.c' } }, req, res, () => {});
      expect(res.statusCode).toBe(400);
      // 标题声明「能取到字段名」——必须断言日志里的字段名，否则整条路径
      // 退化成「反正 400 就算过」；连带把 keyPattern 分支的字段名也钉住
      const logger = require('../../utils/logger');
      const spy = jest.spyOn(logger, 'warn').mockImplementation(() => {});
      try {
        errorHandler({ code: 11000, keyValue: { email: 'a@b.c' } }, req, buildRes(), () => {});
        expect(spy).toHaveBeenCalledWith(expect.stringContaining('email'));
      } finally {
        spy.mockRestore();
      }
    });
  });

  // ================= P3-35 挂载顺序、留痕与限流口径 =================
  //
  // 【本次改动改造：静态断言 → 行为断言】
  // 审计实测：把 generalLimiter 的 `skip: skipIfWhitelisted` 改成 `() => false`
  // （白名单豁免整体失效），旧的源码文本断言仍然全绿——因为它只检查
  // 源码里是否出现该字符串。P3-35 整块已改为真实驱动中间件/真实 HTTP 请求，
  // 每个用例都能因行为退化而变红（变异验证见各用例注释）。
  describe('P3-35 早期拒绝留痕、限流豁免口径与挂载顺序', () => {
    const { protocolCompliance } = require('../../middleware/protocolCompliance');

    /** 构造最简 req/res，直接驱动中间件（不启动 HTTP 服务） */
    const driveMw = (mw, req) => {
      const res = {
        statusCode: null,
        body: null,
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(payload) {
          this.body = payload;
          return this;
        },
      };
      const next = jest.fn();
      mw(req, res, next);
      return { res, next };
    };
    const mkReq = (over = {}) => ({
      method: 'TRACE',
      originalUrl: '/api/x',
      url: '/api/x',
      headers: {},
      get: () => undefined,
      ip: '203.0.113.10',
      ...over,
    });

    /** 限流器驱动夹具（与 coverageBoostBatch3 同口径：每次新 req，emit finish） */
    const mkLimRes = (statusCode = 401) => {
      const listeners = {};
      const res = {
        _status: null,
        statusCode,
        status(c) {
          this._status = c;
          this.statusCode = c;
          return this;
        },
        json() {
          return this;
        },
        send() {
          return this;
        },
        setHeader() {},
        on(ev, fn) {
          (listeners[ev] = listeners[ev] || []).push(fn);
          return this;
        },
        emit(ev, ...args) {
          (listeners[ev] || []).forEach((fn) => fn(...args));
        },
      };
      return res;
    };
    const mkLimReq = (over = {}) => ({
      ip: '203.0.113.50',
      method: 'GET',
      path: '/x',
      originalUrl: '/x',
      body: {},
      app: { get: () => false },
      headers: {},
      ...over,
    });
    const driveLimiter = async (limiter, baseReq, cap) => {
      const res = mkLimRes();
      const next = jest.fn();
      for (let i = 0; i < cap; i += 1) {
        limiter({ ...baseReq }, res, next);
        await new Promise((r) => setImmediate(r));
        if (res._status === 429) return { hit: i + 1, res, next };
        res.emit('finish');
        await new Promise((r) => setImmediate(r));
      }
      return { hit: null, res, next };
    };

    test('protocolCompliance 挂载早于 body 解析（超限请求由协议层拒绝，错误码可区分）', async () => {
      // 行为判据：协议层 maxContentLength 已与 express.json 的 1mb 对齐。
      // 若挂载顺序反转（body 解析在前），body-parser 会先抛 entity.too.large，
      // 响应错误码变成 PAYLOAD_EXCEEDS_LIMIT；顺序正确时是协议层的
      // PAYLOAD_TOO_LARGE。两个错误码可区分，故本用例能因顺序退化而变红。
      const { createApp } = require('../../app');
      require('../../models/TokenBlacklist');
      const app = createApp();
      const res = await request(app)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .set('Content-Length', String(20 * 1024 * 1024));
      expect(res.status).toBe(413);
      expect(res.body.errors?.errorCode).toBe('PAYLOAD_TOO_LARGE');
    });

    test('探针豁免精确到「GET/HEAD + 精确路径」，方法与前缀子树两个维度都不再免检', () => {
      const mw = protocolCompliance();
      const getProbe = driveMw(
        mw,
        mkReq({ method: 'GET', originalUrl: '/health', url: '/health' })
      );
      expect(getProbe.next).toHaveBeenCalled();

      const headProbe = driveMw(
        mw,
        mkReq({ method: 'HEAD', originalUrl: '/readyz', url: '/readyz' })
      );
      expect(headProbe.next).toHaveBeenCalled();

      // 方法维度：探针路径上的非探针方法回到普通表面（原先不看方法 ⇒ POST /health
      // 可零配额、零闸门地让服务端解析 1MB body）
      const traceProbe = driveMw(mw, mkReq({ originalUrl: '/health', url: '/health' }));
      expect(traceProbe.next).not.toHaveBeenCalled();
      expect(traceProbe.res.statusCode).toBe(405);

      // 路径维度：一个名字免掉整棵子树同样不再成立
      const traceSubtree = driveMw(mw, mkReq({ originalUrl: '/health/x', url: '/health/x' }));
      expect(traceSubtree.next).not.toHaveBeenCalled();
      expect(traceSubtree.res.statusCode).toBe(405);

      const apiHealth = driveMw(mw, mkReq({ originalUrl: '/api/health', url: '/api/health' }));
      expect(apiHealth.next).not.toHaveBeenCalled();
      expect(apiHealth.res.body.errors?.errorCode).toBe('HTTP_METHOD_UNSUPPORTED');
    });

    test('资源型限流器全部豁免白名单 IP（以非白名单的触发点为基准对照）', async () => {
      const limiters = require('../../middleware/rateLimit');
      // 夹具必须是**该限流器真正覆盖的面**。这些是资源型限流器，服务对象是 API 面；
      // 而 mkLimReq 的默认 path 是 '/x'（GET、非 /api）。
      // 2026-09-29 给两个**全站挂载**的资源型限流器（generalLimiter / ipLimiter）加了
      // 「安全方法 + 非 /api 前缀」的静态前端面豁免后，'/x' 落进了豁免面 ⇒
      // generalLimiter 对这条夹具根本不计数，"基准必须触发"就成了假红：
      // CI run #73 实测 `generalLimiter` 期望 triggered:true、实得 false。
      // 这里显式用 /api/ 路径——它对全部五个限流器都是"在范围内"的形状，
      // 基准才真正证明"该限流器确实在计数"。**不要改回 '/x'**。
      const inScope = (over) => mkLimReq({ path: '/api/x', originalUrl: '/api/x', ...over });
      // 每个限流器用独立 IP 建键，避免互相污染计数器
      const cases = [
        ['generalLimiter', '203.0.113.61'],
        ['strictLimiter', '203.0.113.62'],
        ['captchaLimiter', '203.0.113.63'],
        ['ipLimiter', '203.0.113.64'],
        ['userLimiter', '203.0.113.65'],
      ];
      for (const [name, ip] of cases) {
        // 基准：非白名单必须能触发（证明该限流器确实在计数，防「两边都不触发」的假绿）
        const base = await driveLimiter(limiters[name], inScope({ ip }), 1500);
        expect({ name, triggered: base.hit !== null }).toEqual({ name, triggered: true });

        // 白名单：按基准触发次数 + 余量驱动，始终不得触发
        const wl = await driveLimiter(
          limiters[name],
          inScope({ ip, ipWhitelisted: true }),
          base.hit + 5
        );
        expect({ name, status: wl.res._status }).toEqual({ name, status: null });
        expect(wl.next).toHaveBeenCalled();
      }
    });

    test('凭据型限流器刻意不豁免白名单（内网撞库同样受限速）', async () => {
      const limiters = require('../../middleware/rateLimit');
      // loginLimiter：白名单 + 同账号连续尝试必须仍被限速
      const login = await driveLimiter(
        limiters.loginLimiter,
        mkLimReq({
          ip: '203.0.113.71',
          method: 'POST',
          body: { username: 'victim' },
          ipWhitelisted: true,
        }),
        30
      );
      expect(login.hit).not.toBeNull();

      // passwordChangeLimiter：已认证用户组合键，白名单同样受限
      const pwd = await driveLimiter(
        limiters.passwordChangeLimiter,
        mkLimReq({
          ip: '203.0.113.72',
          method: 'PUT',
          body: {},
          user: { userId: 'u-whitelisted' },
          ipWhitelisted: true,
        }),
        15
      );
      expect(pwd.hit).not.toBeNull();
    });

    test('黑名单 403 真实写入早期拒绝审计（ip_blacklist_blocked）', async () => {
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      const AuditLog = require('../../models/AuditLog');
      const IPBlacklist = require('../../models/IPBlacklist');
      const { checkIPBlacklist } = require('../../middleware/security');
      const ip = '198.51.100.31';
      await IPBlacklist.deleteMany({ ip });
      await IPBlacklist.create({ ip, type: 'black', reason: 'p3-35-audit' });

      const recorded = [];
      const spy = jest.spyOn(AuditLog, 'record').mockImplementation((doc) => {
        recorded.push(doc);
        return Promise.resolve(null);
      });
      try {
        const res = {
          statusCode: null,
          body: null,
          status(code) {
            this.statusCode = code;
            return this;
          },
          json(payload) {
            this.body = payload;
            return this;
          },
        };
        const next = jest.fn();
        await checkIPBlacklist(
          { ip, method: 'GET', originalUrl: '/api/x', headers: {}, get: () => undefined },
          res,
          next
        );
        expect(next).not.toHaveBeenCalled();
        expect(res.statusCode).toBe(403);
        // recordEarlyRejection 经 setImmediate 异步落库，轮询等待
        for (
          let i = 0;
          i < 50 && !recorded.some((d) => d.action === 'ip_blacklist_blocked');
          i += 1
        ) {
          await new Promise((r) => setImmediate(r));
        }
        const entry = recorded.find((d) => d.action === 'ip_blacklist_blocked');
        expect(entry).toBeTruthy();
        expect(entry.riskFactors).toContain('ip_blacklisted');
      } finally {
        spy.mockRestore();
        await IPBlacklist.deleteMany({ ip });
      }
    });

    test('checkIPBlacklist 挂载早于 CORS（黑名单 403 不带 CORS 响应头）', async () => {
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      require('../../models/TokenBlacklist');
      const IPBlacklist = require('../../models/IPBlacklist');
      const { createApp } = require('../../app');
      // 测试环境 trust proxy 关闭，X-Forwarded-For 不参与 req.ip 计算，
      // 故直接封禁环回地址本身（supertest 的连接源）。
      // 顺序：先测未封禁（对照），再封禁测拦截——反向顺序会被
      // checkIPBlacklist 的进程内降级缓存（5 分钟 TTL）污染。
      const app = createApp();
      const unblocked = await request(app).get('/api').set('Origin', 'http://localhost:3001');
      expect(unblocked.status).toBe(200);
      expect(unblocked.headers['access-control-allow-origin']).toBe('http://localhost:3001');

      await IPBlacklist.deleteMany({ $or: [{ ip: '127.0.0.1' }, { ip: '::ffff:127.0.0.1' }] });
      await IPBlacklist.create({ ip: '127.0.0.1', type: 'black', reason: 'p3-35-cors-order' });
      try {
        const blocked = await request(app).get('/api').set('Origin', 'http://localhost:3001');
        expect(blocked.status).toBe(403);
        // CORS 若已执行会回显 ACAO；黑名单在 CORS 之前拒绝则无此头。
        // 变异：把 app.js 的 app.use(checkIPBlacklist) 移到 cors() 之后，本断言变红。
        expect(blocked.headers['access-control-allow-origin']).toBeUndefined();
      } finally {
        await IPBlacklist.deleteMany({ $or: [{ ip: '127.0.0.1' }, { ip: '::ffff:127.0.0.1' }] });
        require('../../middleware/security').invalidateIPBlockCache('::ffff:127.0.0.1');
        require('../../middleware/security').invalidateIPBlockCache('127.0.0.1');
      }
    });

    test('checkIPBlacklist 不再挂在 applyPostBodySecurity 内（单独挂载时不拦截）', async () => {
      const express = require('express');
      const { applyPostBodySecurity } = require('../../middleware/security');
      const probe = express();
      applyPostBodySecurity(probe);
      probe.get('/probe', (req, res) => res.json({ reached: true }));
      const res = await request(probe).get('/probe');
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ reached: true });
    });

    test('originCheck 对白名单 IP 豁免（非常规 Origin 也放行）', async () => {
      const express = require('express');
      const { createOriginCheck } = require('../../middleware/originCheck');
      const build = (whitelisted) => {
        const app = express();
        app.use((req, _res, next) => {
          if (whitelisted) req.ipWhitelisted = true;
          next();
        });
        app.use(createOriginCheck(['http://good.example']));
        app.post('/x', (req, res) => res.json({ ok: true }));
        return app;
      };
      const denied = await request(build(false)).post('/x').set('Origin', 'http://evil.example');
      expect(denied.status).toBe(403);
      const allowed = await request(build(true)).post('/x').set('Origin', 'http://evil.example');
      expect(allowed.status).toBe(200);
      expect(allowed.body).toEqual({ ok: true });
    });

    test('queryLengthLimit 对白名单豁免，但 queryScalarGuard 不豁免（形态约束非限流）', () => {
      const { queryLengthLimit, queryScalarGuard } = require('../../middleware/queryLimit');
      const mk = () => ({
        statusCode: null,
        body: null,
        status(c) {
          this.statusCode = c;
          return this;
        },
        json(b) {
          this.body = b;
          return this;
        },
      });
      const long = 'a'.repeat(300);

      // 非白名单：两者都必须拦（证明豁免不是「一律放行」）
      const r1 = mk();
      const n1 = jest.fn();
      queryLengthLimit(200)({ query: { q: long }, ipWhitelisted: false }, r1, n1);
      expect(n1).not.toHaveBeenCalled();
      expect(r1.statusCode).toBe(400);

      const r2 = mk();
      const n2 = jest.fn();
      queryScalarGuard()({ query: { a: { $ne: 1 } }, ipWhitelisted: false }, r2, n2);
      expect(n2).not.toHaveBeenCalled();
      expect(r2.statusCode).toBe(400);

      // 白名单：queryLengthLimit 仍豁免（体量/频次型约束可信任内网）
      const r3 = mk();
      const n3 = jest.fn();
      queryLengthLimit(200)({ query: { q: long }, ipWhitelisted: true }, r3, n3);
      expect(n3).toHaveBeenCalled();
      expect(r3.statusCode).toBeNull();

      // 但 queryScalarGuard 对白名单**不再豁免**：Express 5 下 sanitizeMongo/hpp 对
      // req.query 清洗失效，本函数是 query 侧唯一防线，对象/数组取值对任何来源一律 400，
      // 否则白名单来源可把 {"$ne":...} 操作符直送 mongoose 过滤条件（旧实现的归零点）。
      const r4 = mk();
      const n4 = jest.fn();
      queryScalarGuard()({ query: { a: { $ne: 1 } }, ipWhitelisted: true }, r4, n4);
      expect(n4).not.toHaveBeenCalled();
      expect(r4.statusCode).toBe(400);
    });

    test('docsLimiter 对白名单 IP 豁免（不豁免时同配额下必触发 429）', async () => {
      const swagger = require('../../config/swagger');
      const drive = async (ip, whitelisted, cap) => {
        const res = mkLimRes(200);
        const next = jest.fn();
        for (let i = 0; i < cap; i += 1) {
          swagger.docsLimiter(
            mkLimReq({ ip, method: 'GET', originalUrl: '/api-docs/', ipWhitelisted: whitelisted }),
            res,
            next
          );
          await new Promise((r) => setImmediate(r));
          if (res._status === 429) return i + 1;
        }
        return null;
      };
      // 配额默认 30：非白名单同 IP 必须在 30 次附近触发（上下留 1 次格式差异余量）
      const hitAt = await drive('203.0.113.81', false, 60);
      expect(hitAt).not.toBeNull();
      expect(hitAt).toBeGreaterThanOrEqual(29);
      expect(hitAt).toBeLessThanOrEqual(31);
      // 白名单：同 IP 驱动 60 次始终不超限
      const wlHit = await drive('203.0.113.82', true, 60);
      expect(wlHit).toBeNull();
    });
  });

  // ================= P3-36 注释/配置漂移 =================
  describe('P3-36 注释与实现对齐', () => {
    test('cookie.js 不再写死与 config 默认值不符的具体时长', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../utils/cookie.js'), 'utf8');
      const contract = source.slice(source.indexOf('契约（I-01）'), source.indexOf('项目未引入'));
      // 契约段落里不得出现写死的小时数——JWT_EXPIRE 由配置决定
      expect(contract).not.toMatch(/JWT_EXPIRE\s*\(\s*\d+\s*h\s*\)/);
      expect(contract).toMatch(/maxAge 与 JWT_EXPIRE 一致/);
    });

    test('config 的 corsOrigin 注释描述真实回退行为（固定白名单，非回显来源）', () => {
      // 【本次改动加固】原断言只查注释里出现「固定」「白名单」——把注释改回
      // 「未配置时反射请求来源」后仍绿（改写后的句子同样可含这两个词）。
      // 现按「错误说法必须被显式否定」断言，并保留正向描述。
      const source = fs.readFileSync(path.join(__dirname, '../../config/index.js'), 'utf8');
      const before = source.slice(0, source.indexOf('corsOrigin:'));
      const commentBlock = before.slice(before.lastIndexOf('// CORS'));
      expect(commentBlock).toMatch(/固定/);
      expect(commentBlock).toMatch(/白名单/);
      // 否定语境：必须点名「反射请求来源」这一错误说法并标明不符
      expect(commentBlock).toMatch(/曾声称「未配置时反射请求来源」——与实现不符/);
      expect(commentBlock).toMatch(/从不回显 Origin/);
    });

    test('corsOrigin 的实际回退行为与注释一致（真实 app：不回显任意来源）', async () => {
      // 注释所描述的行为本身可测：固定白名单外的 Origin 不得被回显
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      require('../../models/TokenBlacklist');
      const { createApp } = require('../../app');
      const app = createApp();
      const evil = await request(app).get('/api').set('Origin', 'http://evil.example');
      expect(evil.headers['access-control-allow-origin']).toBeUndefined();
      const good = await request(app).get('/api').set('Origin', 'http://localhost:3001');
      expect(good.headers['access-control-allow-origin']).toBe('http://localhost:3001');
    });

    test('unref() 实际返回 Timeout 自身（原注释所称的 undefined 不成立）', () => {
      const timer = setInterval(() => {}, 60000);
      expect(timer.unref()).toBe(timer);
      clearInterval(timer);
    });

    test('auth.js 缓存淘汰注释与「插入序」实现一致，不再声称 LRU', () => {
      // 【本次改动加固】原断言只查「插入顺序」字样与一行否定式——把注释改回
      // 「此处原注释称 LRU——按最近使用淘汰」后仍绿（「插入顺序」四字还在）。
      // 现要求错误说法处于**显式否定语境**，并保留对实现事实的陈述。
      const source = fs.readFileSync(path.join(__dirname, '../../middleware/auth.js'), 'utf8');
      const block = source.slice(
        source.indexOf('// 缓存容量保护'),
        source.indexOf('// 查询期间是否发生了主动失效')
      );
      expect(block).toMatch(/插入顺序/);
      // 错误说法必须被点名否定：原注释的「删除最旧的一半」不准确
      expect(block).toMatch(/原注释称「删除最旧的一半」——不准确/);
      expect(block).toMatch(/而非 LRU 意义上的「最久未使用」/);
      // 不得残留任何肯定式 LRU 声明
      expect(block).not.toMatch(/按最近使用淘汰/);
      expect(block).not.toMatch(/此处原注释称 LRU/);
    });
  });
});
