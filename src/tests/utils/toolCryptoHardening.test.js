/**
 * 批次F 工具/密码学类修复回归（P3-26 ~ P3-36）
 *
 * 这批缺陷集中在「工具函数的边界行为」与「注释/配置与实现背离」两类。
 * 前者能直接断言（脱敏结果、解码是否抛错、口令是否被接受），
 * 后者只能锁定「实现侧的不变量」——注释本身无法测试，但注释所描述的行为可以。
 */

const fs = require('fs');
const path = require('path');

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
      const secret = generateSecret();
      const counter = currentCounter();
      const source = fs.readFileSync(path.join(__dirname, '../../utils/totp.js'), 'utf8');

      // 行为断言：窗口内任意偏移都能通过
      for (const offset of [-1, 0, 1]) {
        expect(verifyTotp(secret, codeAt(secret, counter + offset), 1)).toBe(true);
      }

      // 结构断言：比较必须用 timingSafeEqual，且循环体内不得直接 return
      expect(source).toMatch(/timingSafeEqual/);
      const loopBody = source.slice(
        source.indexOf('for (let i = -window'),
        source.indexOf('return matchedCounter')
      );
      expect(loopBody.length).toBeGreaterThan(0);
      expect(loopBody).not.toMatch(/\breturn\b/);
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

    test('securityRoutes 改密校验委托单一实现，不再复刻正则', () => {
      const source = fs.readFileSync(
        path.join(__dirname, '../../routes/securityRoutes.js'),
        'utf8'
      );
      expect(source).toMatch(/validatePasswordStrength/);
      // 旧的独立字符集正则必须已被移除，否则两处口径会再次漂移
      expect(source).not.toMatch(/matches\(\/\[!@#\$%\^&\*/);
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

    test('大小写不同的用户名被唯一索引拒绝', async () => {
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      // 内存库里此前可能残留字段级 unique 生成的 username_1，先同步到 schema 定义
      await User.syncIndexes();
      const base = { password: 'Qz7#Lm42vTx9', realName: '大小写测试' };
      await User.create({ ...base, username: 'CaseTester', email: 'case1@example.com' });
      await expect(
        User.create({ ...base, username: 'casetester', email: 'case2@example.com' })
      ).rejects.toMatchObject({ code: 11000 });
    });

    test('findByUsername 可用任意大小写命中同一账户', async () => {
      const found = await User.findByUsername('CASETESTER');
      expect(found).not.toBeNull();
      expect(found.username).toBe('CaseTester');
    });

    test('索引对账在存在大小写冲突时保留旧索引而非删除（不出现零约束窗口）', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../services/initData.js'), 'utf8');
      const fn = source.slice(
        source.indexOf('const reconcileUserIndexes'),
        source.indexOf('const initializeSystem')
      );
      // 冲突检测必须出现在 dropIndex 之前
      expect(fn.indexOf('$toLower')).toBeLessThan(fn.indexOf("dropIndex('username_1')"));
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

    test('app.js 不再使用会写入完整 query 的 combined 预设', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../app.js'), 'utf8');
      expect(source).not.toMatch(/morgan\('combined'/);
      expect(source).toMatch(/safe-url/);
    });

    test('logger 注册了 exceptionHandlers/rejectionHandlers 且不抢占退出', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../utils/logger.js'), 'utf8');
      expect(source).toMatch(/exceptionHandlers/);
      expect(source).toMatch(/rejectionHandlers/);
      // exitOnError 必须为 false，否则会抢在 index.js 的审计 flush 之前退出
      expect(source).toMatch(/exitOnError:\s*false/);
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
      const res = buildRes();
      errorHandler({ code: 11000, keyPattern: { username: 1 } }, req, res, () => {});
      expect(res.statusCode).toBe(400);
    });

    test('仅有 keyValue 时也能取到字段名', () => {
      const res = buildRes();
      errorHandler({ code: 11000, keyValue: { email: 'a@b.c' } }, req, res, () => {});
      expect(res.statusCode).toBe(400);
    });
  });

  // ================= P3-35 挂载顺序、留痕与限流口径 =================
  describe('P3-35 早期拒绝留痕、限流豁免口径与挂载顺序', () => {
    test('protocolCompliance 挂载早于 body 解析（否则「不读流」的设计意图落空）', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../app.js'), 'utf8');
      const preIdx = source.indexOf('applyPreBodySecurity(app)');
      // 必须匹配实际挂载语句，不能只匹配 'express.json('——
      // 上方注释里也提到该函数名，会命中注释而非挂载点
      const jsonIdx = source.indexOf('app.use(express.json(');
      const postIdx = source.indexOf('applyPostBodySecurity(app)');
      expect(preIdx).toBeGreaterThan(-1);
      expect(jsonIdx).toBeGreaterThan(-1);
      expect(preIdx).toBeLessThan(jsonIdx);
      expect(jsonIdx).toBeLessThan(postIdx);
    });

    test('skipPaths 不再含从不存在的 /api/health 死配置', () => {
      const source = fs.readFileSync(
        path.join(__dirname, '../../middleware/protocolCompliance.js'),
        'utf8'
      );
      const decl = source.slice(source.indexOf('skipPaths ='), source.indexOf('} = options'));
      expect(decl).not.toMatch(/'\/api\/health'/);
      expect(decl).toMatch(/'\/health'/);
    });

    test('资源型限流器全部挂 skipIfWhitelisted', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../middleware/rateLimit.js'), 'utf8');
      for (const name of [
        'generalLimiter',
        'strictLimiter',
        'captchaLimiter',
        'ipLimiter',
        'userLimiter',
      ]) {
        const body = source.slice(source.indexOf(`const ${name} = rateLimit({`));
        const decl = body.slice(0, body.indexOf('});'));
        expect(decl).toMatch(/skip:\s*skipIfWhitelisted/);
      }
    });

    test('凭据型限流器刻意不豁免白名单（内网撞库同样受限速）', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../middleware/rateLimit.js'), 'utf8');
      for (const name of [
        'loginLimiter',
        'loginIpLimiter',
        'loginUserLimiter',
        'passwordChangeLimiter',
      ]) {
        const body = source.slice(source.indexOf(`const ${name} = rateLimit({`));
        const decl = body.slice(0, body.indexOf('});'));
        expect(decl).not.toMatch(/skip:\s*skipIfWhitelisted/);
      }
    });

    test('黑名单 403 与 CSRF 403 均调用早期拒绝审计', () => {
      const security = fs.readFileSync(
        path.join(__dirname, '../../middleware/security.js'),
        'utf8'
      );
      const origin = fs.readFileSync(
        path.join(__dirname, '../../middleware/originCheck.js'),
        'utf8'
      );
      expect(security).toMatch(/recordEarlyRejection/);
      expect(origin).toMatch(/recordEarlyRejection/);
    });

    test('新增的早期拒绝 action 已进入审计筛选白名单', () => {
      const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
      for (const action of [
        'ip_blacklist_blocked',
        'csrf_origin_denied',
        'malformed_request_blocked',
      ]) {
        expect(AUDIT_LOG_ACTIONS).toContain(action);
      }
    });

    test('checkIPBlacklist 挂载早于 CORS（黑名单在一切协商/解析之前拒绝）', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../app.js'), 'utf8');
      const ipIdx = source.indexOf('app.use(checkIPBlacklist)');
      // 允许 app.use( 与 cors( 之间被格式化工具插入换行/缩进
      const corsMatch = source.match(/app\.use\(\s*cors\(/);
      const corsIdx = corsMatch ? corsMatch.index : -1;
      expect(ipIdx).toBeGreaterThan(-1);
      expect(corsIdx).toBeGreaterThan(-1);
      expect(ipIdx).toBeLessThan(corsIdx);
    });

    test('checkIPBlacklist 不再挂在 applyPostBodySecurity 内（已前置到 CORS 之前）', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../middleware/security.js'), 'utf8');
      const postStart = source.indexOf('const applyPostBodySecurity');
      const postBlock = source.slice(postStart, source.indexOf('module.exports'));
      expect(postBlock).not.toMatch(/app\.use\(checkIPBlacklist\)/);
    });

    test('originCheck 对白名单 IP 豁免', () => {
      const source = fs.readFileSync(
        path.join(__dirname, '../../middleware/originCheck.js'),
        'utf8'
      );
      expect(source).toMatch(/req\.ipWhitelisted\s*===\s*true/);
    });

    test('queryLengthLimit / queryScalarGuard 对白名单 IP 豁免', () => {
      const source = fs.readFileSync(
        path.join(__dirname, '../../middleware/queryLimit.js'),
        'utf8'
      );
      // 两个中间件函数体都应包含豁免判断
      const lenStart = source.indexOf('function queryLengthLimit');
      const guardStart = source.indexOf('function queryScalarGuard');
      expect(source.slice(lenStart, guardStart)).toMatch(/req\.ipWhitelisted\s*===\s*true/);
      expect(source.slice(guardStart)).toMatch(/req\.ipWhitelisted\s*===\s*true/);
    });

    test('docsLimiter 对白名单 IP 豁免', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../config/swagger.js'), 'utf8');
      expect(source).toMatch(/skip:\s*\(req\)\s*=>\s*req\.ipWhitelisted\s*===\s*true/);
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
      const source = fs.readFileSync(path.join(__dirname, '../../config/index.js'), 'utf8');
      const before = source.slice(0, source.indexOf('corsOrigin:'));
      const commentBlock = before.slice(before.lastIndexOf('// CORS'));
      // 断言注释描述的是实现真正做的事：回退到固定开发白名单
      expect(commentBlock).toMatch(/固定/);
      expect(commentBlock).toMatch(/白名单/);
    });

    test('unref() 实际返回 Timeout 自身（原注释所称的 undefined 不成立）', () => {
      const timer = setInterval(() => {}, 60000);
      expect(timer.unref()).toBe(timer);
      clearInterval(timer);
    });

    test('auth.js 缓存淘汰注释与「插入序」实现一致，不再声称 LRU', () => {
      const source = fs.readFileSync(path.join(__dirname, '../../middleware/auth.js'), 'utf8');
      const block = source.slice(
        source.indexOf('// 缓存容量保护'),
        source.indexOf('// 查询期间是否发生了主动失效')
      );
      expect(block).toMatch(/插入顺序/);
      expect(block).not.toMatch(/删除最旧的一半$/m);
    });
  });
});
