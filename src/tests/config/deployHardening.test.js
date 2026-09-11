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

    test('docker-compose 不再用 environment 传任何密钥', () => {
      const yml = readRoot('docker-compose.yml');
      const appEnvBlock = yml.slice(yml.indexOf('    environment:'), yml.indexOf('    secrets:'));
      // 这些变量若出现在 environment（且非 _FILE 形式）即回归
      for (const key of [
        'JWT_SECRET',
        'JWT_REFRESH_SECRET',
        'AES_SECRET_KEY',
        'HMAC_SECRET',
        'MONGODB_URI',
      ]) {
        expect(appEnvBlock).not.toMatch(new RegExp(`- ${key}=`));
        expect(appEnvBlock).toMatch(new RegExp(`- ${key}_FILE=`));
      }
      // mongo 服务同理走 _FILE
      expect(yml).toMatch(/MONGO_INITDB_ROOT_PASSWORD_FILE=/);
      expect(yml).not.toMatch(/- MONGO_INITDB_ROOT_PASSWORD=/);
      // 顶层 secrets 段必须存在
      expect(yml).toMatch(/^secrets:$/m);
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
