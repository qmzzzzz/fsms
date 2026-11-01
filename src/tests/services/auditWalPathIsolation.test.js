/**
 * L-28 回归：审计 WAL 默认路径不得全局共享
 *
 * 缺陷：原默认值为固定的 logs/audit-buffer.wal。两个进程 cwd 相同即共写一个文件，
 * 后果不是覆盖而是更隐蔽的**交叉重放**——A 重启时把 B 未落库的行也读进来落库，
 * B 稍后再落一次同一批 → 审计记录重复、哈希链分叉。
 *
 * 本测试锁定两点：
 *   1. 默认路径按库名派生（同机不同库 → 不同文件）
 *   2. 显式 AUDIT_WAL_PATH 优先（向后兼容，运维可控）
 */
const path = require('path');

const MODULE_PATH = path.resolve(__dirname, '../../services/auditBuffer');

/**
 * 在隔离的子进程中解析 WAL 路径，避免污染当前进程的 env 与模块缓存。
 *
 * 注意：AUDIT_WAL_PATH 是在 start() 时读取的（设计如此——见 auditBuffer.js 文件头，
 * 为了让测试套件能按 worker 重指向），因此探针必须走 start()→getWalPath()→stop()
 * 这条真实路径，而不是只加载模块就读路径。
 */
function walPathWith(env) {
  const { execFileSync } = require('child_process');
  const probe = `
    const m = require(${JSON.stringify(MODULE_PATH)});
    m.start();
    const p = m.getWalPath();
    m.stop();
    process.stdout.write('WALPATH=' + String(p) + '\\n');
  `;
  const out = execFileSync(process.execPath, ['-e', probe], {
    cwd: path.resolve(__dirname, '../../..'),
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  // 子进程会同时输出它自己的日志（例如 ACL 收紧告警，含时间戳与 pid）：
  // 直接 trim 整段 stdout 会把"两次运行日志不同"误判成"WAL 路径不同"。
  // 只认探针显式打的那一行标记，日志多少条都不影响本闸的判据。
  const markerLines = out.split(/\r?\n/).filter((l) => l.startsWith('WALPATH='));
  // 恰好一条：既能防「探针没打标记」，也能防日志里混进第二份路径（例如某个分支把路径打到了 stdout）。
  if (markerLines.length !== 1) {
    throw new Error(
      `WALPATH 标记行应恰好 1 条，实际 ${markerLines.length} 条：${out.slice(0, 500)}`
    );
  }
  const walPath = markerLines[0].slice('WALPATH='.length).trim();
  // 除标记行外，stdout 不得再出现这条路径：WAL 的绝对路径属于宿主内部信息，
  // 泄漏到子进程日志里等于把「库名 + 部署目录」写给每一条日志的读者。
  // 唯一豁免是 ACL 收紧的两条告警——它们的工作就是报告「哪个文件没能收紧」，
  // 而本机（Windows 且无 USERNAME）必然失败、Linux 上顺利收紧则根本不出现。
  const aclNoise = /审计 WAL .*权限未能收紧|无法确定当前用户名/;
  const leaked = out
    .split(/\r?\n/)
    .filter((l) => !l.startsWith('WALPATH='))
    .filter((l) => !aclNoise.test(l))
    .filter((l) => walPath && l.includes(walPath));
  expect(leaked).toEqual([]);
  return walPath.replace(/\\/g, '/');
}

describe('L-28 审计 WAL 默认路径按库名派生', () => {
  const saved = {};
  beforeAll(() => {
    saved.uri = process.env.MONGODB_URI;
    saved.wal = process.env.AUDIT_WAL_PATH;
  });
  afterAll(() => {
    if (saved.uri === undefined) delete process.env.MONGODB_URI;
    else process.env.MONGODB_URI = saved.uri;
    if (saved.wal === undefined) delete process.env.AUDIT_WAL_PATH;
    else process.env.AUDIT_WAL_PATH = saved.wal;
  });

  it('同一 MONGODB_URI 下稳定派生同一个文件名（重启前后一致 → WAL 才能跨重启恢复）', () => {
    delete process.env.AUDIT_WAL_PATH;
    process.env.MONGODB_URI = 'mongodb://localhost:27017/fire_safety_db';
    const a = walPathWith({});
    const b = walPathWith({});
    expect(a).toBe(b);
    expect(a).toContain('fire_safety_db');
  });

  it('不同库名 → 不同 WAL 文件（同机多进程不再交叉重放）', () => {
    const a = walPathWith({
      MONGODB_URI: 'mongodb://localhost:27017/db_alpha',
      AUDIT_WAL_PATH: '',
    });
    const b = walPathWith({ MONGODB_URI: 'mongodb://localhost:27017/db_beta', AUDIT_WAL_PATH: '' });
    expect(a).not.toBe(b);
    expect(a).toContain('db_alpha');
    expect(b).toContain('db_beta');
  });

  it('带认证信息的 URI 也能正确取库名（不被 user:pass 干扰）', () => {
    const p = walPathWith({
      MONGODB_URI: 'mongodb://user:pass@mongo:27017/prod_db?authSource=admin',
      AUDIT_WAL_PATH: '',
    });
    expect(p).toContain('prod_db');
    expect(p).not.toContain('user');
    expect(p).not.toContain('pass');
  });

  it('显式 AUDIT_WAL_PATH 优先级最高（运维可控，向后兼容）', () => {
    const p = walPathWith({
      MONGODB_URI: 'mongodb://localhost:27017/whatever',
      AUDIT_WAL_PATH: '/tmp/explicit-override.wal',
    });
    expect(p).toContain('explicit-override.wal');
  });

  it('无 MONGODB_URI 时回退历史默认值（单实例行为不变）', () => {
    const p = walPathWith({ MONGODB_URI: '', AUDIT_WAL_PATH: '' });
    expect(p).toMatch(/logs\/audit-buffer\.wal$/);
  });

  it('派生的文件名不含路径分隔符（普通库名的常规形态）', () => {
    const p = walPathWith({
      MONGODB_URI: 'mongodb://localhost:27017/normal_db',
      AUDIT_WAL_PATH: '',
    });
    // 必须在 logs/ 目录下，且文件名形如 audit-buffer.<db>.wal
    expect(p).toMatch(/\/logs\/audit-buffer\.[^/]+\.wal$/);
  });

  /**
   * L-30：上一条用例的**旧版本**名为「不含路径分隔符注入」，但载荷是 normal_db ——
   * 它从未构造过任何注入形态，测不出 decodeURIComponent 把 %2F 还原成 /
   * 之后的目录穿越（实测：db%2F..%2F..%2Fevil → <仓库根>/evil.wal，逃出 logs/）。
   * 本用例喂真实载荷，断言派生结果必须仍落在 logs/ 内。
   */
  it('库名含编码路径分隔符（%2F / %5C）时不得逃出 logs/（路径穿越防护）', () => {
    const logsDir = path.resolve(__dirname, '../../..', 'logs').split(path.sep).join('/');
    const payloads = [
      'db%2F..%2F..%2Fevil', // 编码斜杠 + 多级回退
      'db%5C..%5C..%5Cevil', // 编码反斜杠（Windows 分隔符）
      '%2Fetc%2Fpasswd', // 解码后为绝对路径片段
      'db%2F..%2F..%2F..%2F..%2Fpwn', // 深度回退
    ];
    for (const dbName of payloads) {
      const p = walPathWith({
        MONGODB_URI: 'mongodb://localhost:27017/' + dbName,
        AUDIT_WAL_PATH: '',
      });
      // 双重断言：目录归属 + 文件名形态（后者能抓住「逃出被文件名巧合掩盖」的情况）
      expect(p.startsWith(logsDir + '/')).toBe(true);
      expect(p).toMatch(/\/logs\/audit-buffer(\.[^/\\]+)?\.wal$/);
    }
  });

  it('不同库名必须映射到不同 WAL 文件（消毒不得引入碰撞 → 防交叉重放回潮）', () => {
    // 下划线替换类消毒会让 db/x 与 db_x 撞成同一文件——那正是 L-28 要消除的
    // 交叉重放。此处用「非法字符与合法字符」成对构造，断言路径互不相同。
    const pairs = [
      ['mongodb://localhost:27017/db/x', 'mongodb://localhost:27017/db_x'],
      ['mongodb://localhost:27017/a b', 'mongodb://localhost:27017/a_b'],
      ['mongodb://localhost:27017/a:b', 'mongodb://localhost:27017/a_b'],
    ];
    for (const [ua, ub] of pairs) {
      const a = walPathWith({ MONGODB_URI: ua, AUDIT_WAL_PATH: '' });
      const b = walPathWith({ MONGODB_URI: ub, AUDIT_WAL_PATH: '' });
      expect(a).not.toBe(b);
    }
  });

  it('合法库名不受消毒影响（文件名保持可读的恒等形态）', () => {
    const p = walPathWith({
      MONGODB_URI: 'mongodb://localhost:27017/fire_safety_db',
      AUDIT_WAL_PATH: '',
    });
    expect(p).toMatch(/audit-buffer\.fire_safety_db\.wal$/);
  });
});

/**
 * D9：把「隔离粒度到库为止」变成可断言的事实，而不是注释里的承诺。
 *
 * 缺陷（audit-round11-auditchain D8/D9 一族的低危项）：默认路径只按库名派生，
 * 所以**同一库的多个实例共用同一个默认 WAL 文件**，谁后写谁赢；L-28 只是把交叉
 * 重放从「同机任意进程」收窄到「同库多实例」，并没有消除它。修 D9 时不改行为
 * （改行为会动到线上路径），只把前提写进注释并让它从返回值可观测——
 * resolveWalPath().scope 就是那个观测点。
 *
 * 判据刻意是纯函数直调（不经 auditBuffer.start() 子系统）：要钉的是「派生规则
 * 承认自己的粒度」，与 WAL 落盘、ACL、重放幂等那些运行时性质无关。
 */
describe('D9 派生结果的隔离粒度必须可观测（同库多实例共用默认路径）', () => {
  const SAVED = process.env.MONGODB_URI;
  const walPath = require('../../services/auditWalPath');
  afterAll(() => {
    if (SAVED === undefined) delete process.env.MONGODB_URI;
    else process.env.MONGODB_URI = SAVED;
  });

  it('有库名 ⇒ scope=per-database，且 path 与旧入口 deriveDefaultWalPath() 逐字一致', () => {
    process.env.MONGODB_URI = 'mongodb://localhost:27017/fire_safety_db';
    const info = walPath.deriveDefaultWalPathInfo();
    // 粒度只到库：这一条是 D9 的核心断言，注释里的前提必须能从返回值读到
    expect(info.scope).toBe('per-database');
    expect(info.dbName).toBe('fire_safety_db');
    expect(info.path).toMatch(/audit-buffer\.fire_safety_db\.wal$/);
    // 兼容入口不得漂移：拆分前后调用方拿到的字符串必须一模一样
    expect(walPath.deriveDefaultWalPath()).toBe(info.path);
  });

  it('同一库派生两次得到同一路径（同库多实例共用的直接证据，不是「各实例各一份」）', () => {
    process.env.MONGODB_URI = 'mongodb://localhost:27017/shared_db';
    const a = walPath.deriveDefaultWalPathInfo();
    const b = walPath.deriveDefaultWalPathInfo();
    expect(a.path).toBe(b.path);
    expect(a.scope).toBe('per-database');
    // 换库才分家——隔离维度的边界在第 1 段（库名），不在实例
    process.env.MONGODB_URI = 'mongodb://localhost:27017/other_db';
    expect(walPath.deriveDefaultWalPathInfo().path).not.toBe(a.path);
  });

  it('无库名可用 ⇒ scope=shared-fallback（历史默认值：此时连库级隔离都没有）', () => {
    delete process.env.MONGODB_URI;
    const info = walPath.deriveDefaultWalPathInfo();
    expect(info.scope).toBe('shared-fallback');
    expect(info.dbName).toBe(null);
    expect(info.path).toMatch(/logs[\\/]audit-buffer\.wal$/);
  });
});
