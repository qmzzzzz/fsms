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
