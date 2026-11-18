/**
 * scripts/verify-audit-export.js 端到端：
 *   生成的清单能通过校验；改 CSV 字节、改 manifest 字段、换密钥都必须被抓到；
 *   未签名文件默认只能算"校验不完整"（退出码 2），显式放行才退 0。
 */

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  buildAuditExportManifest,
  MANIFEST_LINE_PREFIX,
  EXPORT_CSV_HEADER,
} = require('../../services/auditExportService');

const SCRIPT = path.resolve(__dirname, '../../../scripts/verify-audit-export.js');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

const run = (args, env = process.env) => {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
      encoding: 'utf8',
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { code: 0, output: stdout };
  } catch (err) {
    return { code: err.status, output: `${err.stdout || ''}${err.stderr || ''}` };
  }
};

const buildFile = () => {
  const rows = [
    [
      '2026-09-08T00:00:00.000Z',
      'auth_login',
      'auth',
      'u1',
      '127.0.0.1',
      '/api/auth/login',
      '200',
      'true',
      'low',
      '',
      'a'.repeat(64),
    ],
    [
      '2026-09-08T00:00:01.000Z',
      'auth_logout',
      'auth',
      'u2',
      '127.0.0.1',
      '/api/auth/logout',
      '200',
      'true',
      'low',
      'a'.repeat(64),
      'b'.repeat(64),
    ],
  ];
  const csvPart = `${EXPORT_CSV_HEADER}\n${rows.map((cells) => cells.join(',')).join('\n')}\n`;
  const csvBuf = Buffer.from(csvPart, 'utf8');
  const manifest = buildAuditExportManifest({
    recordCount: rows.length,
    chainRecords: rows.length,
    startTime: new Date('2026-09-08T00:00:00.000Z'),
    endTime: new Date('2026-09-08T00:00:01.000Z'),
    sha256: sha256(Buffer.from(rows.map((cells) => cells[10]).join(''), 'utf8')),
    csvSha256: sha256(csvBuf),
    csvBytes: csvBuf.length,
    truncated: false,
  });
  return { csvBuf, manifest };
};

const writeFile = (dir, name, csvBuf, manifest) => {
  const target = path.join(dir, name);
  fs.writeFileSync(
    target,
    Buffer.concat([csvBuf, Buffer.from(`${MANIFEST_LINE_PREFIX}${JSON.stringify(manifest)}\n`)]),
    'utf8'
  );
  return target;
};

describe('verify-audit-export.js', () => {
  let dir;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-export-verify-'));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('合法导出：字节、链摘要与 HMAC 全部通过', () => {
    const { csvBuf, manifest } = buildFile();
    expect(manifest.signature).toBeDefined();
    const file = writeFile(dir, 'ok.csv', csvBuf, manifest);

    const result = run([file]);

    expect(result.code).toBe(0);
    expect(result.output).toContain('校验通过');
    expect(result.output).toContain(`keyId=${manifest.signature.keyId}`);
  });

  test('改 CSV 字节：文件摘要先红，退出码 1', () => {
    const { csvBuf, manifest } = buildFile();
    const tampered = Buffer.from(csvBuf);
    const at = tampered.indexOf(Buffer.from('u1'));
    tampered[at] = 'x'.charCodeAt(0);
    const file = writeFile(dir, 'tampered-csv.csv', tampered, manifest);

    const result = run([file]);

    expect(result.code).toBe(1);
    expect(result.output).toContain('文件字节摘要不匹配');
  });

  test('改 manifest 字段（签名仍在）：HMAC 失配，退出码 1', () => {
    const { csvBuf, manifest } = buildFile();
    const tampered = { ...manifest, truncated: true, notice: '伪造的截断说明' };
    const file = writeFile(dir, 'tampered-manifest.csv', csvBuf, tampered);

    const result = run([file]);

    expect(result.code).toBe(1);
    expect(result.output).toContain('manifest 签名不匹配');
  });

  test('换密钥：HMAC 失配，退出码 1', () => {
    const { csvBuf, manifest } = buildFile();
    const file = writeFile(dir, 'wrong-key.csv', csvBuf, manifest);

    const result = run([file], {
      ...process.env,
      HMAC_SECRET: 'x'.repeat(64),
      HMAC_SECRET_FILE: '',
    });

    expect(result.code).toBe(1);
    expect(result.output).toContain('manifest 签名不匹配');
  });

  test('未签名：默认退出码 2（校验不完整），显式放行后退 0', () => {
    const { csvBuf, manifest } = buildFile();
    const unsigned = { ...manifest };
    delete unsigned.signature;
    const file = writeFile(dir, 'unsigned.csv', csvBuf, unsigned);

    const strict = run([file]);
    expect(strict.code).toBe(2);
    expect(strict.output).toContain('未签名');

    const allowed = run([file, '--allow-no-signature']);
    expect(allowed.code).toBe(0);
    expect(allowed.output).toContain('已显式放行');
  });

  test('缺少 manifest 尾行：退出码 2，不把半截文件当成功', () => {
    const file = path.join(dir, 'no-manifest.csv');
    fs.writeFileSync(file, `${EXPORT_CSV_HEADER}\n`, 'utf8');

    const result = run([file]);

    expect(result.code).toBe(2);
    expect(result.output).toContain('未找到 manifest');
  });
});

/**
 * 2026-11-17 审计（可测化）：脚本原在模块顶层无条件执行 main()，判据函数无法单测。
 * 现已加 require.main 守卫并导出判据函数——本块直接 require 脚本模块逐个验证。
 */
describe('verify-audit-export.js 可测化：require 守卫与判据函数', () => {
  // 这行 require 本身就是守卫判据：main() 若仍在模块级无条件执行，
  // parseArgs([]) 会因缺 CSV 路径 process.exit(2)，下面的断言永远走不到。
  const scriptModule = require('../../../scripts/verify-audit-export');

  test('require 不触发执行；判据函数与交付格式常量可导入', () => {
    for (const fn of [
      'parseArgs',
      'splitExport',
      'parseCsv',
      'verifyFileDigest',
      'verifyChainDigest',
      'verifySignature',
      'verifyGeneratedAt',
    ]) {
      expect(typeof scriptModule[fn]).toBe('function');
    }
    expect(scriptModule.EXPECTED_HEADER).toBe(EXPORT_CSV_HEADER);
  });

  test('parseCsv：CRLF 的 CR 不入内容；引号转义与字段内换行按 RFC 4180', () => {
    expect(scriptModule.parseCsv('a,b\r\nc,d\r\n')).toEqual([
      ['a', 'b'],
      ['c', 'd'],
    ]);
    expect(scriptModule.parseCsv('"x""y",z')).toEqual([['x"y', 'z']]);
    expect(scriptModule.parseCsv('"p\nq",r')).toEqual([['p\nq', 'r']]);
  });

  test('splitExport：从尾行切出 manifest；csvPart 不含 manifest 行；无尾行返回 null', () => {
    const raw = Buffer.from(`h1\n${MANIFEST_LINE_PREFIX}{"a":1}\n`, 'utf8');
    const split = scriptModule.splitExport(raw);
    expect(split.manifest).toEqual({ a: 1 });
    expect(split.csvPart.toString('utf8')).toBe('h1\n');
    expect(scriptModule.splitExport(Buffer.from('no manifest here\n', 'utf8'))).toBeNull();
  });

  test('verifyGeneratedAt：签发时间在未来超过 5 分钟 ⇒ exit 1（stub 取证，不真退进程）', () => {
    const exitSpy = jest.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`process.exit:${code}`);
    });
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(() =>
        scriptModule.verifyGeneratedAt({
          generatedAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
        })
      ).toThrow(/process\.exit:1/);
      expect(exitSpy).toHaveBeenCalledWith(1);
    } finally {
      exitSpy.mockRestore();
      errSpy.mockRestore();
    }
  });

  test('parseArgs：未知参数与缺文件路径都以 exit 2 拒绝', () => {
    const exitSpy = jest.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`process.exit:${code}`);
    });
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(() => scriptModule.parseArgs(['--bogus'])).toThrow(/process\.exit:2/);
      expect(() => scriptModule.parseArgs([])).toThrow(/process\.exit:2/);
      expect(exitSpy).toHaveBeenCalledWith(2);
    } finally {
      exitSpy.mockRestore();
      errSpy.mockRestore();
    }
  });
});
