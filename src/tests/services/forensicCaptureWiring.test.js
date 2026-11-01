/**
 * 取证捕获的生产接线（P1-4 回归）
 *
 * 判据只认"src/index.js 里真的有这些调用点"，不认"模块导出了这个函数"——
 * 导出齐备却没人调，是这轮审计里最典型的一类"看着做完了、其实没跑起来"：
 * start() 不调 ⇒ WAL 永不重放、flush 定时器不存在，只有攒够 50 条才被动落库。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

describe('index.js 必须真的驱动取证捕获的生命周期', () => {
  const src = read('src/index.js');

  test('require 了 forensicCapture 模块', () => {
    expect(src).toMatch(/require\('\.\/services\/forensicCapture'\)/);
  });

  test('启动段调用 start()（WAL 重放 + 定时 flush）', () => {
    expect(src).toMatch(/forensicCapture\.start\(\);/);
  });

  test('关停段调用 flushAndStop() 并如实上报 residual', () => {
    expect(src).toMatch(/forensicCapture\.flushAndStop\(/);
    // residual>0 必须进 error 分支（与审计缓冲同一口径），不得只打"已排空"
    expect(src).toMatch(/取证捕获缓冲未排空/);
  });

  test('崩溃两臂（uncaughtException / unhandledRejection）都排空取证缓冲', () => {
    const crashFlush = src.match(/\.then\(\(\) => forensicCapture\.flush\(\)\)/g) || [];
    expect(crashFlush.length).toBe(2);
  });
});
