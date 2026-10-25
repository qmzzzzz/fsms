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
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const PIN = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'deployment/ip2region-checksum.json'), 'utf8')
);
const { checkPin, digest, loadPin, CHECKSUM_FILE } = require(
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
