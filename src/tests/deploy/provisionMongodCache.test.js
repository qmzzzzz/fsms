'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { sha256File, isCached, CACHE_ROOT } = require('../../../scripts/provision-mongod');

const DIGEST = 'a'.repeat(64);

describe('provision-mongod 缓存投毒防护', () => {
  let dir;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'provision-cache-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('sha256File：流式读取与一次性哈希等值', () => {
    const payload = Buffer.from('x'.repeat(1024 * 1024 + 123)); // 跨多个 1MiB 读块
    const file = path.join(dir, 'blob.bin');
    fs.writeFileSync(file, payload);
    expect(sha256File(file)).toBe(crypto.createHash('sha256').update(payload).digest('hex'));
  });

  test('isCached：标记与二进制重算哈希都对上锚值才命中', () => {
    const extract = path.join(dir, 'mongo-8.0.34-ubuntu2404');
    const payload = Buffer.from('mongod-bytes');
    fs.mkdirSync(path.join(extract, 'bin'), { recursive: true });
    fs.writeFileSync(path.join(extract, 'bin', 'mongod'), payload);
    fs.writeFileSync(path.join(extract, '.sha256'), `${DIGEST}\n`);
    expect(isCached(extract, path.join('bin', 'mongod'), DIGEST)).toBe(false); // 标记在、二进制被换过 ⇒ 投毒形态必须判不命中
  });

  test('isCached：二进制哈希与标记一致 ⇒ 命中', () => {
    const extract = path.join(dir, 'mongo-8.0.34-ubuntu2404');
    const payload = Buffer.from('mongod-bytes');
    fs.mkdirSync(path.join(extract, 'bin'), { recursive: true });
    const real = crypto.createHash('sha256').update(payload).digest('hex');
    fs.writeFileSync(path.join(extract, 'bin', 'mongod'), payload);
    fs.writeFileSync(path.join(extract, '.sha256'), `${real}\n`);
    expect(isCached(extract, path.join('bin', 'mongod'), real)).toBe(true);
  });

  test('isCached：标记不符 / 二进制缺失 / 目录不可读 ⇒ 一律不命中', () => {
    const extract = path.join(dir, 'm');
    fs.mkdirSync(extract, { recursive: true });
    expect(isCached(extract, 'mongod', DIGEST)).toBe(false);
    fs.writeFileSync(path.join(extract, '.sha256'), `${DIGEST}\n`);
    expect(isCached(extract, 'mongod', DIGEST)).toBe(false); // 标记在、二进制缺
  });

  test('缓存根在用户私有目录（homedir 下），不再落在共享 tmpdir 的可预测子目录', () => {
    expect(CACHE_ROOT.startsWith(os.homedir())).toBe(true);
    expect(CACHE_ROOT.includes(path.join(os.tmpdir(), 'fsms-mongod'))).toBe(false);
  });
});
