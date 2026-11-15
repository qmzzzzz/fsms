/**
 * ip2region.xdb 内容锚回归（2026-10-24 审计 P3）
 *
 * 结构探针只能证明「格式像数据」，证明不了「字节就是评审过的那份」。
 * 本测试锁住三条：仓库内文件与 deployment/ip2region-checksum.json 逐字节一致、
 * 锚字段形状合法、比对函数对任何变异都判失败（防止 checkPin 退化成恒真）。
 */

const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const PIN = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'deployment/ip2region-checksum.json'), 'utf8')
);
const { checkPin, digest, loadPin, CHECKSUM_FILE, assertPathAbsent, randomTmpName } = require(
  path.join(ROOT, 'scripts/update-ip2region.js')
);

const DATA = fs.readFileSync(path.join(ROOT, PIN.file));

describe('ip2region 内容锚', () => {
  test('锚字段形状合法（sha256 64 位 hex + 整数 bytes）', () => {
    expect(PIN.file).toBe('src/data/ip2region.xdb');
    expect(PIN.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(Number.isInteger(PIN.bytes)).toBe(true);
    expect(PIN.bytes).toBeGreaterThan(1024 * 1024);
  });

  test('仓库内数据与锚逐字节一致', () => {
    expect(DATA.length).toBe(PIN.bytes);
    expect(digest(DATA)).toBe(PIN.sha256);
    expect(checkPin(DATA, PIN).ok).toBe(true);
  });

  test('loadPin 读到的就是本测试用的同一份锚', () => {
    expect(CHECKSUM_FILE).toBe(path.join(ROOT, 'deployment/ip2region-checksum.json'));
    expect(loadPin()).toEqual(PIN);
  });

  test('变异样本必须判失败（字节数不变也要靠哈希识别）', () => {
    const flipped = Buffer.from(DATA);
    flipped[flipped.length - 1] ^= 0x01;
    const empty = Buffer.alloc(0);
    expect(checkPin(flipped, PIN)).toEqual({
      ok: false,
      actual: { bytes: DATA.length, sha256: digest(flipped) },
    });
    expect(checkPin(empty, PIN).ok).toBe(false);
  });

  test('--check 在真实文件上以 0 退出', () => {
    const out = execFileSync(
      process.execPath,
      [path.join(ROOT, 'scripts/update-ip2region.js'), '--check'],
      {
        encoding: 'utf8',
      }
    );
    expect(out).toContain('内容锚一致');
  });

  test('digest 与独立计算一致（锚算法未被偷换）', () => {
    expect(digest(Buffer.from('fsms'))).toBe(
      crypto.createHash('sha256').update('fsms').digest('hex')
    );
  });
});

describe('update-ip2region 原子替换的临时文件加固（2026-11-15 审计）', () => {
  test('临时名带 pid 与随机后缀，不再固定为 .tmp', () => {
    const base = '/repo/src/data/ip2region.xdb';
    const a = randomTmpName(base);
    const b = randomTmpName(base);
    expect(a).not.toBe(b); // 随机后缀：并发运行与预置攻击都难以命中同一个名字
    expect(a).toContain(`.${process.pid}-`);
    expect(a.endsWith('.tmp')).toBe(true);
    expect(a.startsWith(`${base}.`)).toBe(true);
  });

  test('assertPathAbsent：不存在的路径放行；已存在（含悬空符号链接）一律拒绝', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ip2region-tmp-'));
    try {
      expect(() => assertPathAbsent(path.join(dir, 'free.tmp'))).not.toThrow();
      fs.writeFileSync(path.join(dir, 'occupied'), 'x');
      expect(() => assertPathAbsent(path.join(dir, 'occupied'))).toThrow(/拒绝写入/);
      const link = path.join(dir, 'dangling.link');
      try {
        fs.symlinkSync(path.join(dir, 'no-such-target'), link);
        expect(() => assertPathAbsent(link)).toThrow(/拒绝写入/); // 悬空链接也算已占用
      } catch (err) {
        if (err.code !== 'EPERM') throw err; // Windows 非开发者模式建链 EPERM：本平台测不到该腿
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
