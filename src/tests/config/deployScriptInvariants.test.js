/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：部署脚本与配置（.sh/.bat/.cmd/.yml）的静态不变量
 * 守护的不变式：凭据不上命令行、私钥 chmod、taskkill 前校验映像名、留存期单一声明
 * 可证伪性：变异实测（筛查 N=2）：杀 3/3
 *
 * ⚠️ 既往审计指出的边界（2026-09-20 逐条**内容复核**；原报告行号已漂移，按代码特征取证）
 *   标记：[仍有效] 复核后问题依旧 / [已修复] 已被后续修复解决 / [部分有效] 仅部分成立 /
 *   [已自陈] 用例内已记录并给出保留理由。复核证据见 `deliverables/AGENT工作总账与待办-2026-09-21.md` §2.9 测试资产。
 *   - [仍有效·已实测] `:363-367`（现形 `:127-135`）用 grep 源码断"变量名存在" ⇒ 机制坏了用例仍绿（源码文本正则断言的失效形态，deliverables/七维代码健康度深度审计-2026-09-18.md）
 *     变异实测确认（2026-09-20，`deliverables/AGENT工作总账与待办-2026-09-21.md` §6 方法）：断言 `expect(fn).toMatch(/wasAdjusted/)`
 *       只查 `checkRetention` 函数**文本里出现该标识符**。把 scripts/compliance-check.js:56 的
 *       `const passed = meetsMinimum && !wasAdjusted;` 改成 `const passed = meetsMinimum;`
 *       （机制破坏、文本保留）→ **33/33 全绿**；**文本级正对照**（全函数把 wasAdjusted 改名
 *       wasClamped）→ 1 例红。⚠️ 文本孤岛断言结构上无法用 throw 做正对照，只能用文本级正对照。
 *
 * 命名沿革：2026-09-20 由 `deployHardening.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * 批次H 工程/部署/测试类修复回归（P3-46 ~ P3-51）
 *
 * 这批缺陷的载体多为脚本与配置文件（.sh / .bat / .cmd / yml），无法直接
 * 单元测试其运行时行为，因此断言分两层：
 *  - 能在 Node 里求值的部分（留存期单一声明、密钥文件注入）做行为断言；
 *  - 脚本类做「关键不变量的静态断言」——锁定那些一旦被改回去就会重新
 *    引入缺陷的特征（凭据不上命令行、私钥 chmod、taskkill 前校验映像名等）。
 */

const fs = require('fs');
const path = require('path');
const os = require('os');

const ROOT = path.join(__dirname, '..', '..', '..');
/** 读取仓库根目录下的文件（脚本类断言用） */
const readRoot = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/**
 * ==== docker-compose.yml 的扫描器（全部接受文本参数，不读文件）====
 * 之所以做成纯函数：判据必须能被**合成源**反向自证——真实 compose 是共享文件，
 * 为了证明闸门有效而临时往里插一行明文密钥，等于让并发会话有机会撞上它。
 * 本仓踩过两次的那类坑也在此一并堵掉：本仓库文件是 CRLF，
 * 用 `:\n` 这类硬换行锚点会让正则恒不匹配、断言恒绿，所以一律先 split(/\r?\n/)。
 */

/** app 服务 environment 段的列表行（不含注释与空行）；结构取不到时返回 null */
function appEnvironmentLines(yml) {
  const rows = yml.split(/\r?\n/);
  const appAt = rows.findIndex((l) => l === '  app:');
  if (appAt < 0) return null;
  const envAt = rows.findIndex((l, i) => i > appAt && /^ {4}environment:\s*$/.test(l));
  if (envAt < 0) return null;
  const out = [];
  for (let i = envAt + 1; i < rows.length; i += 1) {
    // 下一个服务级键（4 空格缩进且非列表项）⇒ environment 段结束
    if (/^ {4}\S/.test(rows[i])) break;
    if (/^ {6}-\s/.test(rows[i])) out.push(rows[i]);
  }
  return out;
}

/** app environment 里以 `- NAME=值` **明文**出现的文件型密钥名 */
function plaintextSecretNames(yml, names) {
  const lines = appEnvironmentLines(yml);
  // 切片失败不许静默放行：全部按违规上报，让用例红到结构本身
  if (!lines) return names.slice();
  return names.filter((name) => lines.some((l) => new RegExp(`^\\s*- ${name}=\\S*$`).test(l)));
}

/** app environment 里某个变量的值（没有该变量返回 null） */
function appEnvValue(yml, name) {
  const line = (appEnvironmentLines(yml) || []).find((l) =>
    new RegExp(`^\\s*- ${name}=(\\S*)$`).test(l)
  );
  return line ? /^\s*- [A-Z0-9_]+=(\S*)$/.exec(line)[1] : null;
}

/** app 服务级 `secrets:` 列表声明的挂载名 */
function serviceSecretList(yml) {
  const rows = yml.split(/\r?\n/);
  const appAt = rows.findIndex((l) => l === '  app:');
  if (appAt < 0) return [];
  const at = rows.findIndex((l, i) => i > appAt && /^ {4}secrets:\s*$/.test(l));
  if (at < 0) return [];
  const out = [];
  for (let i = at + 1; i < rows.length; i += 1) {
    const m = /^ {6}- (\S+)$/.exec(rows[i]);
    if (!m) break;
    out.push(m[1]);
  }
  return out;
}

/** 顶层 `secrets:` 段：键 + 其 file: 目标（缺 file: 时 file 为 null） */
function topLevelSecrets(yml) {
  const rows = yml.split(/\r?\n/);
  const at = rows.findIndex((l) => l === 'secrets:');
  if (at < 0) return [];
  const out = [];
  for (let i = at + 1; i < rows.length; i += 1) {
    if (/^(volumes|networks):\s*$/.test(rows[i])) break;
    const k = /^ {2}([a-z0-9_]+):\s*$/.exec(rows[i]);
    if (!k) continue;
    const f = /^ {4}file:\s*(\S+)\s*$/.exec(rows[i + 1] || '');
    out.push({ name: k[1], file: f ? f[1] : null });
  }
  return out;
}

/**
 * environment 里的 `/run/secrets/<名>` 引用与两处声明的一致性总览。
 * 漏声明的后果不是"没密钥"而是"启动即崩"：hydrateSecretsFromFiles 对不可读的
 * _FILE 直接抛错（src/config/secrets.js:99-107），运维看到的是一条与密钥无关的启动失败。
 */
function secretMountAudit(yml) {
  const referenced = (appEnvironmentLines(yml) || [])
    .map((l) => /^\s*- [A-Z0-9_]+_FILE=\/run\/secrets\/([a-z0-9_]+)\s*$/.exec(l))
    .filter(Boolean)
    .map((m) => m[1]);
  const declared = serviceSecretList(yml);
  const topLevel = topLevelSecrets(yml).map((s) => s.name);
  return {
    referenced,
    missingFromService: referenced.filter((n) => !declared.includes(n)),
    missingFromTopLevel: referenced.filter((n) => !topLevel.includes(n)),
  };
}

describe('批次H 工程与部署加固回归', () => {
  // ================= P3-46 留存期单一声明 =================
  describe('P3-46 审计留存期单一声明与合规检查', () => {
    const RETENTION_ENV = 'AUDIT_RETENTION_DAYS';
    let savedEnv;

    beforeEach(() => {
      savedEnv = process.env[RETENTION_ENV];
    });
    afterEach(() => {
      if (savedEnv === undefined) delete process.env[RETENTION_ENV];
      else process.env[RETENTION_ENV] = savedEnv;
      jest.resetModules();
    });

    /** 在指定环境变量下重新加载 constants/retention */
    const loadWith = (value) => {
      if (value === undefined) delete process.env[RETENTION_ENV];
      else process.env[RETENTION_ENV] = value;
      jest.resetModules();
      return require('../../constants/retention');
    };

    test('未配置时取默认 180 天，且不标记为「被调整」', () => {
      const r = loadWith(undefined);
      expect(r.RETENTION_DAYS).toBe(180);
      expect(r.isConfigured).toBe(false);
      expect(r.wasAdjusted).toBe(false);
    });

    test('区间内取值原样生效', () => {
      const r = loadWith('200');
      expect(r.RETENTION_DAYS).toBe(200);
      expect(r.wasAdjusted).toBe(false);
      expect(r.RETENTION_SECONDS).toBe(200 * 24 * 60 * 60);
    });

    test('低于合规下限被钳制到 90，并标记为「被调整」', () => {
      // 原缺陷：compliance-check 先钳制再断言 >= 90，永真。
      // 这里锁定「钳制发生了」这一事实必须可被观测
      const r = loadWith('1');
      expect(r.RETENTION_DAYS).toBe(90);
      expect(r.RAW_RETENTION_DAYS).toBe(1);
      expect(r.wasAdjusted).toBe(true);
    });

    test('负值同样被钳制（原实现会让 logger 得到非法的 maxFiles: -5d）', () => {
      const r = loadWith('-5');
      expect(r.RETENTION_DAYS).toBe(90);
      expect(r.wasAdjusted).toBe(true);
    });

    test('超过上限被钳制到 3650', () => {
      const r = loadWith('99999');
      expect(r.RETENTION_DAYS).toBe(3650);
      expect(r.wasAdjusted).toBe(true);
    });

    test('非数值回退默认并标记为「被调整」', () => {
      const r = loadWith('abc');
      expect(r.RETENTION_DAYS).toBe(180);
      expect(r.isConfigured).toBe(false);
      expect(r.wasAdjusted).toBe(true);
    });

    // F-213：解析器必须是**严格**的。`parseInt(x, 10)` 会吃掉尾部垃圾并交出前缀数字，
    // 于是"配置被静默改写过"这一事实根本不会被标记——与 P3-46 立这个单源时的
    // 承诺（"二者不等即说明运维配置被静默修正过"）正相反：静默的恰好是那一类。
    test('带尾数的取值不得被静默截断成前缀（parseInt("90x")=90 且"未调整"）', () => {
      const dirty = loadWith('90x');
      expect(dirty.RETENTION_DAYS).toBe(180);
      expect(dirty.isConfigured).toBe(false);
      expect(dirty.wasAdjusted).toBe(true);
      expect(dirty.describeRetention()).toMatch(/无法解析/);
      // 反向对照（防"一律判非法"的实现也绿）：同一个数字写干净就必须原样生效
      const clean = loadWith('90');
      expect(clean.RETENTION_DAYS).toBe(90);
      expect(clean.isConfigured).toBe(true);
      expect(clean.wasAdjusted).toBe(false);
    });

    test('科学计数法不得塌成 1（parseInt("1e3",10)=1 → 被钳到合规下限 90）', () => {
      const r = loadWith('1e3');
      expect(r.RETENTION_DAYS).toBe(1000);
      expect(r.RAW_RETENTION_DAYS).toBe(1000);
      expect(r.wasAdjusted).toBe(false);
      expect(r.RETENTION_SECONDS).toBe(1000 * 24 * 60 * 60);
    });

    test('空串仍按「未配置数值」处理，而不是 Number("")=0 被当成 0 天', () => {
      const r = loadWith('');
      expect(r.RETENTION_DAYS).toBe(180);
      expect(r.isConfigured).toBe(false);
      expect(r.wasAdjusted).toBe(true);
    });

    // F-213：说明文本必须与数字来自**同一份加载期快照**。
    // 原先 isConfigured / RETENTION_DAYS 在 require 时定，describeRetention() 却现读
    // process.env ⇒ 同一句里两半的时点不同。
    // 只有"加载期配了个解析不出的值"这条分支才暴露得出来（有效值的文案取 RETENTION_DAYS，
    // 现读不现读都一样）——本用例因此特意走 '90x' 而不是 '200'。
    test('describeRetention 读的是加载期快照，不是调用时刻的 process.env', () => {
      const prevEnv = process.env[RETENTION_ENV];
      const r = loadWith('90x'); // 加载期：配置了、但解析不出来 ⇒ 生效值来自默认
      try {
        expect(r.describeRetention()).toMatch(/无法解析/);
        // 调用期把变量删掉：环境里已经没有它了，但本模块的结论不能跟着改口
        delete process.env[RETENTION_ENV];
        expect(r.RETENTION_DAYS).toBe(180);
        expect(r.describeRetention()).toMatch(/无法解析/);
        expect(r.describeRetention()).not.toMatch(/未配置/);
      } finally {
        // 自己收干净：本 describe 的 afterEach 只恢复它自己 beforeEach 抓到的值，
        // 留一个非默认值在这里就是文件内顺序耦合（双 seed 门禁专门抓这一类）
        if (prevEnv === undefined) delete process.env[RETENTION_ENV];
        else process.env[RETENTION_ENV] = prevEnv;
      }
    });

    test('describeRetention 对四种情形给出可区分的说明', () => {
      expect(loadWith(undefined).describeRetention()).toMatch(/未配置/);
      expect(loadWith('200').describeRetention()).toMatch(/原样生效/);
      expect(loadWith('1').describeRetention()).toMatch(/超出允许区间/);
      expect(loadWith('abc').describeRetention()).toMatch(/无法解析/);
    });

    test('AuditLog 的 TTL 与 logger 的 maxFiles 引用同一声明（不再各自解析）', () => {
      const auditLogSrc = readRoot('src/models/AuditLog.js');
      const loggerSrc = readRoot('src/utils/logger.js');
      const ctrlSrc = readRoot('src/controllers/securityController.js');

      for (const src of [auditLogSrc, loggerSrc, ctrlSrc]) {
        // 不得再出现各自 parseInt(process.env.AUDIT_RETENTION_DAYS)
        expect(src).not.toMatch(/parseInt\(\s*process\.env\.AUDIT_RETENTION_DAYS/);
      }
      expect(auditLogSrc).toMatch(/constants\/retention/);
      expect(loggerSrc).toMatch(/constants\/retention/);
      expect(ctrlSrc).toMatch(/constants\/retention/);
    });

    test('compliance-check 的留存检查不再是恒真断言', () => {
      const src = readRoot('scripts/compliance-check.js');
      const fn = src.slice(
        src.indexOf('function checkRetention'),
        src.indexOf('// ================= 2.')
      );
      // 恒真的特征：钳制后再与同一下限比较。现在必须把 wasAdjusted 纳入判定
      expect(fn).toMatch(/wasAdjusted/);
      expect(fn).not.toMatch(/Math\.min\(Math\.max\(/);
    });
  });

  // ================= P3-47 运维脚本 =================
  describe('P3-47 证书生成与启动脚本', () => {
    test('generate-dev-cert.sh 显式收紧私钥权限，不依赖调用者 umask', () => {
      const sh = readRoot('scripts/generate-dev-cert.sh');
      expect(sh).toMatch(/umask 077/);
      expect(sh).toMatch(/chmod 600 "\$KEY"/);
      // 证书目录本身也应收紧
      expect(sh).toMatch(/chmod 700 "\$OUT_DIR"/);
    });

    test('generate-dev-cert.sh 拒绝覆盖已存在的证书，并在失败时清理残件', () => {
      const sh = readRoot('scripts/generate-dev-cert.sh');
      // 覆盖正在被加载的证书会导致 TLS 握手失败，且旧私钥不可找回
      expect(sh).toMatch(/拒绝覆盖/);
      expect(sh).toMatch(/trap cleanup_on_failure EXIT/);
    });

    test('generate-dev-cert.sh 用配置文件而非 -subj 传主体（规避 MSYS 路径转换）', () => {
      const sh = readRoot('scripts/generate-dev-cert.sh');
      // -subj "/CN=..." 在 Git Bash 下会被改写成 C:/Program Files/Git/CN=...
      expect(sh).not.toMatch(/-subj\s+"\/CN=/);
      expect(sh).toMatch(/-config "\$CONF"/);
      expect(sh).toMatch(/subjectAltName = DNS:localhost, IP:127\.0\.0\.1/);
    });

    test('start.bat 为 UTF-8 无 BOM 且首行切换到 UTF-8 代码页', () => {
      const buf = fs.readFileSync(path.join(ROOT, 'start.bat'));
      // BOM 会让 cmd 把 EF BB BF 当命令的一部分
      expect(buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf).toBe(false);
      const text = buf.toString('utf8');
      // 必须能按 UTF-8 无损解码（存在替换字符说明不是合法 UTF-8）
      expect(text).not.toContain('\uFFFD');
      expect(text).toMatch(/^@echo off\r\n/);
      expect(text).toMatch(/chcp 65001 >nul/);
      // .bat 多行脚本必须 CRLF
      expect(/(?<!\r)\n/.test(text)).toBe(false);
    });

    test('start.bat 清理端口前校验进程映像名，不再无条件 taskkill', () => {
      const bat = readRoot('start.bat');
      // 原实现：for /f ... do taskkill /F /PID %%a —— 会误杀占用 3000 的任何进程
      expect(bat).not.toMatch(/LISTENING"'\)\s*do taskkill/);
      expect(bat).toMatch(/tasklist \/FI "PID eq/);
      expect(bat).toMatch(/if \/I "%IMAGE_NAME%"=="node\.exe"/);
      // 非 node 进程只告警
      expect(bat).toMatch(/端口被非 node 进程占用/);
    });

    test('start.bat 的端口匹配要求端口号后跟空格（避免 :3000 命中 :30000）', () => {
      const bat = readRoot('start.bat');
      const matches = bat.match(/findstr \/R \/C:":[^"]+"/g) || [];
      expect(matches.length).toBeGreaterThan(0);
      for (const m of matches) {
        expect(m).toMatch(/:\S+ \.\*LISTENING/);
      }
    });

    test('dev-backend.cmd 为纯 ASCII（.cmd 按控制台代码页解码，中文会乱码）', () => {
      const buf = fs.readFileSync(path.join(ROOT, 'dev-backend.cmd'));
      const nonAscii = [...buf].filter((b) => b > 127);
      expect(nonAscii).toEqual([]);
      expect(/(?<!\r)\n/.test(buf.toString('ascii'))).toBe(false);
    });

    test('dev-backend.cmd 有指数退避与快速失败上限，不再是固定 3 秒无限重启', () => {
      const cmd = readRoot('dev-backend.cmd');
      expect(cmd).toMatch(/MAX_FAST_FAILS/);
      expect(cmd).toMatch(/set \/a DELAY=DELAY\*2/);
      expect(cmd).toMatch(/if !DELAY! gtr !MAX_DELAY!/);
      // 正常退出不应重启
      expect(cmd).toMatch(/if !EXIT_CODE! equ 0/);
      // 达到上限后必须退出而非继续 goto loop
      expect(cmd).toMatch(/goto fatal/);
    });

    test('dev-backend.cmd 用 ping 计时而非 timeout（输出重定向时 timeout 会报错）', () => {
      const cmd = readRoot('dev-backend.cmd');
      expect(cmd).toMatch(/ping -n !PING_COUNT! 127\.0\.0\.1 >nul/);
      // 不得出现 timeout 命令调用（注释里提到无妨，故只排除行首命令形式）
      const codeLines = cmd.split(/\r?\n/).filter((l) => !/^\s*REM\b/i.test(l));
      expect(codeLines.some((l) => /^\s*timeout\s/i.test(l))).toBe(false);
    });
  });

  // ================= P3-48 密钥不走环境变量 =================
  describe('P3-48 密钥文件注入', () => {
    let tmpDir;
    const ENV_KEYS = [
      'JWT_SECRET',
      'JWT_SECRET_FILE',
      'JWT_REFRESH_SECRET',
      'JWT_REFRESH_SECRET_FILE',
      'AES_SECRET_KEY',
      'AES_SECRET_KEY_FILE',
      'HMAC_SECRET',
      'HMAC_SECRET_FILE',
    ];
    const saved = {};

    beforeAll(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'xf-secret-test-'));
    });

    afterAll(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    beforeEach(() => {
      for (const k of ENV_KEYS) {
        saved[k] = process.env[k];
        delete process.env[k];
      }
      jest.resetModules();
    });

    afterEach(() => {
      for (const k of ENV_KEYS) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
      jest.resetModules();
    });

    /** 写入密钥文件并返回路径 */
    const writeSecret = (name, content) => {
      const p = path.join(tmpDir, name);
      fs.writeFileSync(p, content, 'utf8');
      return p;
    };

    const hydrate = () => require('../../config/secrets').hydrateSecretsFromFiles();

    test('从 <NAME>_FILE 指向的文件注入到 process.env[NAME]', () => {
      process.env.JWT_SECRET_FILE = writeSecret('jwt', 'super-secret-value-0000000000000000');
      const { loaded, warnings } = hydrate();
      expect(loaded).toContain('JWT_SECRET');
      expect(warnings).toEqual([]);
      expect(process.env.JWT_SECRET).toBe('super-secret-value-0000000000000000');
    });

    test('剥离尾部换行（多数密钥工具与 echo > file 都会追加 \\n）', () => {
      // 带着 \n 做 HMAC/AES 密钥会得到与预期不同的密钥，症状是「解密全部失败」
      process.env.AES_SECRET_KEY_FILE = writeSecret('aes', 'aes-key-0000000000000000\r\n');
      hydrate();
      expect(process.env.AES_SECRET_KEY).toBe('aes-key-0000000000000000');
    });

    test('剥离前导 UTF-8 BOM（记事本编辑的 secret 文件 / 带 BOM 的挂载产物）', () => {
      // Node 的 utf8 解码不剥 BOM：不处理时服务带着"错密钥"成功启动，
      // 所有 enc:v1: 密文 GCM 认证失败 ⇒ MFA 全量报「验证码错误」，
      // 表现与用户输错码一致，排查会被带偏。BOM 与尾部换行同时出现也要干净。
      process.env.AES_SECRET_KEY_FILE = writeSecret('bom', '\uFEFFaes-key-0000000000000000\n');
      const { warnings } = hydrate();
      expect(process.env.AES_SECRET_KEY).toBe('aes-key-0000000000000000');
      expect(warnings).toEqual([]);
    });

    test('内容只有 BOM 时按空文件抛错（而不是带着 \\uFEFF 单字符密钥启动）', () => {
      process.env.JWT_SECRET_FILE = writeSecret('bom-only', '\uFEFF');
      expect(() => hydrate()).toThrow(/为空/);
    });

    test('首尾空格保持原样但必须告警（只在 BOM 上自动裁剪）', () => {
      // 静默裁空格会复现 BOM 那条的同一症状（密钥变了、既有密文全解不开），
      // 而"空格是不是密钥的一部分"只有运维知道，所以这里改口径为只喊不改。
      process.env.HMAC_SECRET_FILE = writeSecret('padded', '  padded-key-value  \n');
      const { warnings } = hydrate();
      expect(process.env.HMAC_SECRET).toBe('  padded-key-value  ');
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/首尾含空白字符/);
    });

    test('同时提供 NAME 与 NAME_FILE 且取值不同时以文件为准并告警', () => {
      // 静默优先其中之一在密钥轮换场景下极危险：运维以为换了文件，实际仍用旧值
      process.env.HMAC_SECRET = 'stale-env-value';
      process.env.HMAC_SECRET_FILE = writeSecret('hmac', 'fresh-file-value');
      const { warnings } = hydrate();
      expect(process.env.HMAC_SECRET).toBe('fresh-file-value');
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/同时配置/);
    });

    test('取值相同时不产生告警（幂等重启不刷噪音）', () => {
      process.env.HMAC_SECRET = 'same-value';
      process.env.HMAC_SECRET_FILE = writeSecret('hmac-same', 'same-value');
      expect(hydrate().warnings).toEqual([]);
    });

    test('文件不存在时抛错，不静默跳过', () => {
      // 跳过会让服务带空密钥启动，随后被另一个不相关的错误信息拦下，误导排查
      process.env.JWT_SECRET_FILE = path.join(tmpDir, 'does-not-exist');
      expect(() => hydrate()).toThrow(/不可读/);
    });

    test('文件为空时抛错', () => {
      process.env.JWT_SECRET_FILE = writeSecret('empty', '\n');
      expect(() => hydrate()).toThrow(/为空/);
    });

    test('未配置任何 _FILE 时不做任何事', () => {
      const { loaded, warnings } = hydrate();
      expect(loaded).toEqual([]);
      expect(warnings).toEqual([]);
    });

    test('密钥注入发生在 config 读取 env 之前（否则拿到空串）', () => {
      const configSrc = readRoot('src/config/index.js');
      const hydrateIdx = configSrc.indexOf('hydrateSecretsFromFiles()');
      const jwtReadIdx = configSrc.indexOf('process.env.JWT_SECRET');
      expect(hydrateIdx).toBeGreaterThan(-1);
      expect(hydrateIdx).toBeLessThan(jwtReadIdx);
    });

    test('compose 不再用 environment 传任何密钥（清单取自 FILE_BACKED_SECRETS，不写死）', () => {
      // 原判据把名字清单抄在断言里（5 个），而 FILE_BACKED_SECRETS 有 15 个：
      // 剩下 10 个（DOCS_PASSWORD / LOG_SHIPPING_TOKEN / METRICS_TOKEN /
      // SECURITY_ALERT_WEBHOOK_SECRET / SENTRY_DSN / LOGIN_ECDH_PRIVATE_KEY / REDIS_URL …）
      // 哪天被写成 `- X=${X}` 明文注入，这条闸一声不响。
      // 清单从 src/config/secrets.js 反向推导：新增文件型密钥不需要回来改用例，
      // 与 compose 的 `:?` 变量清单闸（deployWorkflow.test.js）同一套路。
      const { FILE_BACKED_SECRETS } = require('../../config/secrets');
      const yml = readRoot('docker-compose.yml');
      const envLines = appEnvironmentLines(yml);
      // 前提自证：切片真的切到了 app 的 environment 段。
      // 取不到时 plaintextSecretNames 会一律判违规（恒红，可发现）；
      // 真正难防的是"切到了但只切到一小段"，所以直接数 _FILE 行的条数。
      expect(FILE_BACKED_SECRETS.length).toBeGreaterThanOrEqual(15);
      expect(envLines.filter((l) => /_FILE=/.test(l)).length).toBeGreaterThanOrEqual(7);

      // 唯一豁免：REDIS_URL 以明文出现。豁免不写在注释里，而是条件就地可执行——
      // redis 只挂在 internal 数据网（data-net: internal: true），本仓约定它的 URL
      // 不含凭据（口令走 REDIS_PASSWORD_FILE）。有人图省事写成 `redis://:pw@redis:6379`
      // 的那一刻，这条豁免就变成明文密钥注入，本用例当场判红。
      expect(plaintextSecretNames(yml, FILE_BACKED_SECRETS)).toEqual(['REDIS_URL']);
      expect(/\/\/[^/@]*@/.test(appEnvValue(yml, 'REDIS_URL') || '')).toBe(false);

      // 核心四密钥 + 连接串必须确实是 _FILE 形态（只挡明文不够：漏接线时应用读到空串）
      for (const key of [
        'JWT_SECRET',
        'JWT_REFRESH_SECRET',
        'AES_SECRET_KEY',
        'HMAC_SECRET',
        'MONGODB_URI',
      ]) {
        expect(envLines.some((l) => new RegExp(`^\\s*- ${key}_FILE=`).test(l))).toBe(true);
      }
      // mongo 服务同理走 _FILE
      expect(yml).toMatch(/MONGO_INITDB_ROOT_PASSWORD_FILE=/);
      expect(yml).not.toMatch(/- MONGO_INITDB_ROOT_PASSWORD=/);
      // 顶层 secrets 段必须存在
      expect(yml).toMatch(/^secrets:$/m);

      // ==== 反向自证（合成源：真实 compose 是并发会话共享的文件，不临时改它）====
      // ① 把某个 _FILE 换回明文注入 ⇒ 必须抓到。换成 DOCS_PASSWORD 是有意义的第二次：
      //    原判据把清单写死成 5 个名字，对第 6+ 个文件型密钥完全无感。
      const evil = yml.replace(
        '      - HMAC_SECRET_FILE=/run/secrets/hmac_secret',
        '      - HMAC_SECRET=${HMAC_SECRET}'
      );
      expect(evil).not.toBe(yml);
      expect(plaintextSecretNames(evil, FILE_BACKED_SECRETS)).toContain('HMAC_SECRET');
      const evil2 = yml.replace(
        '      - ADMIN_INITIAL_PASSWORD_FILE=/run/secrets/admin_initial_password',
        '      - DOCS_PASSWORD=${DOCS_PASSWORD}'
      );
      expect(evil2).not.toBe(yml);
      expect(plaintextSecretNames(evil2, FILE_BACKED_SECRETS)).toContain('DOCS_PASSWORD');
      // ② REDIS_URL 一旦带上口令，豁免必须立刻不成立
      const evilUrl = yml.replace(
        '      - REDIS_URL=redis://redis:6379',
        '      - REDIS_URL=redis://:s3cr3t@redis:6379'
      );
      expect(evilUrl).not.toBe(yml);
      expect(/\/\/[^/@]*@/.test(appEnvValue(evilUrl, 'REDIS_URL') || '')).toBe(true);
      // ③ 结构塌了不许静默放行：认不出 app 服务的文本，全部名字按违规上报
      expect(plaintextSecretNames('services: {}\n', ['HMAC_SECRET'])).toEqual(['HMAC_SECRET']);
    });

    test('compose 里每个 /run/secrets/<名> 都在服务 secrets 列表与顶层段双重声明', () => {
      // 三处（environment 的 _FILE 值、服务的 secrets 列表、顶层 secrets 段）必须一致。
      // 漏声明的后果不是"没密钥"而是"启动即崩"：hydrateSecretsFromFiles 对不可读的
      // _FILE 直接抛错（src/config/secrets.js），运维看到的是一条与密钥无关的启动失败。
      // 清单从 compose 自己推导，不写死：改 compose 的人不会想起来回来改这条用例。
      const yml = readRoot('docker-compose.yml');
      const audit = secretMountAudit(yml);
      // 前提自证：三处扫描都真的取到了东西（任一取空都会让对应断言恒绿）
      expect(audit.referenced.length).toBeGreaterThanOrEqual(7);
      expect(serviceSecretList(yml).length).toBeGreaterThanOrEqual(audit.referenced.length);
      const targets = topLevelSecrets(yml);
      expect(targets.length).toBeGreaterThanOrEqual(audit.referenced.length);
      expect(targets.every((t) => typeof t.file === 'string')).toBe(true);

      expect(audit.missingFromService).toEqual([]);
      expect(audit.missingFromTopLevel).toEqual([]);
      // 顶层声明的 file: 路径必须落在被 git 与 dockerignore 排除的 ./secrets/ 下——
      // 指到别处等于把密钥放回版本库与构建上下文
      for (const t of targets) expect(t.file).toMatch(/^\.\/secrets\//);

      // ==== 反向自证（自带夹具，与真实文件无关）====
      const CLEAN = [
        'services:',
        '  app:',
        '    environment:',
        '      - A_SECRET_FILE=/run/secrets/a_secret',
        '    secrets:',
        '      - a_secret',
        'secrets:',
        '  a_secret:',
        '    file: ./secrets/a_secret',
        '',
      ].join('\n');
      expect(secretMountAudit(CLEAN)).toEqual({
        referenced: ['a_secret'],
        missingFromService: [],
        missingFromTopLevel: [],
      });
      const ORPHAN = [
        'services:',
        '  app:',
        '    environment:',
        '      - A_SECRET_FILE=/run/secrets/a_secret',
        '      - B_SECRET_FILE=/run/secrets/b_secret',
        '    secrets:',
        '      - a_secret',
        'secrets:',
        '  a_secret:',
        '    file: ./secrets/a_secret',
        '  b_secret:',
        '    file: ./secrets/elsewhere/b_secret',
        '',
      ].join('\n');
      const orphan = secretMountAudit(ORPHAN);
      expect(orphan.referenced).toEqual(['a_secret', 'b_secret']);
      // b_secret 顶层声明了却没挂到 app 上 ⇒ 容器里 /run/secrets/b_secret 不存在
      expect(orphan.missingFromService).toEqual(['b_secret']);
      // 这一处必须是空：判据认的是"两处一致性"，不是一刀切地盯 environment
      expect(orphan.missingFromTopLevel).toEqual([]);
      // file: 指到 ./secrets/ 之外也要能被看见
      expect(topLevelSecrets(ORPHAN).map((t) => t.file)).toEqual([
        './secrets/a_secret',
        './secrets/elsewhere/b_secret',
      ]);
      // 结构缺失 ⇒ 引用数为 0（与上面真实文件的 ≥7 前提自证配成一对，判据不会两头漏）
      expect(secretMountAudit('services: {}\n').referenced).toEqual([]);
    });

    test('secrets 目录被 git 与 docker 构建上下文双重排除', () => {
      expect(readRoot('.gitignore')).toMatch(/^secrets\/$/m);
      expect(readRoot('.dockerignore')).toMatch(/^secrets$/m);
    });

    test('FILE_BACKED_SECRETS 覆盖全部凭据类变量', () => {
      const { FILE_BACKED_SECRETS } = require('../../config/secrets');
      for (const key of [
        'JWT_SECRET',
        'JWT_REFRESH_SECRET',
        'AES_SECRET_KEY',
        'HMAC_SECRET',
        'MONGODB_URI',
        'ADMIN_INITIAL_PASSWORD',
        'DOCS_PASSWORD',
      ]) {
        expect(FILE_BACKED_SECRETS).toContain(key);
      }
    });
  });

  // ================= P3-51 / T-1 测试隔离 =================
  describe('P3-51/T-1 测试隔离（每测试文件独立数据库）', () => {
    test('当前连接指向「文件级」专属数据库', () => {
      // P3-51 按 worker 隔离，T-1 进一步按测试文件隔离：
      // 同 worker 内多文件不再共用一个库，杜绝跨文件数据残留（如残留
      // IP 黑名单导致下一文件合法请求 403 的顺序相关偶发红）
      expect(process.env.MONGODB_URI).toMatch(/\/jest_w\d+_f[a-z0-9]+(\?|$)/);
    });

    test('setup.js 按 JEST_WORKER_ID + 文件级后缀分配库名', () => {
      const src = readRoot('src/tests/setup.js');
      expect(src).toMatch(/JEST_WORKER_ID/);
      expect(src).toMatch(/WORKER_DB_PREFIX/);
      expect(src).toMatch(/fileSuffix/);
    });

    test('globalTeardown 清理全部 worker 库而非只清主库', () => {
      const src = readRoot('src/tests/globalTeardown.js');
      expect(src).toMatch(/listDatabases/);
      expect(src).toMatch(/JEST_WORKER_DB_PREFIX/);
    });

    test('URI 改写是幂等的（重复执行不会叠加库名）', () => {
      const uri = process.env.MONGODB_URI;
      // setup.js 的守卫条件：已含前缀则不再改写
      expect((uri.match(/jest_w/g) || []).length).toBe(1);
    });
  });
});
