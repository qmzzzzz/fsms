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
    process.stdout.write(String(p));
  `;
  const out = execFileSync(process.execPath, ['-e', probe], {
    cwd: path.resolve(__dirname, '../../..'),
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  return out.trim().replace(/\\/g, '/');
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
