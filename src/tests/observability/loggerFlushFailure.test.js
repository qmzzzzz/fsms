/**
 * 落盘失败路径（P1-13 的边界，补于审计复审）
 *
 * 【为什么单独测】loggerFlush 的 try/catch 是**最后一道防线**：进程正处于退出
 * 流程，任何抛错都会把「配置错误退出」变成「异常退出」，退出码与错误信息双双失真。
 * 原实现的 catch 分支此前**没有任何用例覆盖**——把它改成 `throw e` 测试也不会红。
 *
 * 因此这里用真实文件系统制造「写入必然失败」的条件（把 logDir 指向一个**普通文件**
 * 的路径：mkdirSync(file/xxx) 抛 ENOTDIR），断言：
 *   1. 不抛错（调用方是退出流程）；
 *   2. stderr 有留痕（不静默吞掉）；
 *   3. 返回值仍是渲染好的行（调用方据此做后续处理）；
 *   4. 每个目标文件各自失败一次，不会因第一个失败就跳过后面（error 级有 2 个目标）。
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { flushLogsSync } = require('../../utils/loggerFlush');

describe('flushLogsSync 落盘失败路径（不抛错 + stderr 留痕）', () => {
  let tmpRoot;
  let fileNotDir;

  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'fsms-flushfail-'));
    // 造一个「普通文件」占住路径，使其下的 mkdirSync 必然 ENOTDIR
    fileNotDir = path.join(tmpRoot, 'occupied');
    fs.writeFileSync(fileNotDir, 'not a dir', 'utf8');
  });

  afterEach(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  test('logDir 不可创建时不抛错（退出流程不能被二次异常打断）', () => {
    const stderr = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      expect(() =>
        flushLogsSync('error', '注定失败', undefined, {
          logDir: path.join(fileNotDir, 'logs'),
          now: new Date(2026, 8, 17),
        })
      ).not.toThrow();
    } finally {
      stderr.mockRestore();
    }
  });

  test('失败在 stderr 留痕，且指明是哪个文件（便于退出后排查）', () => {
    const stderr = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      flushLogsSync('error', '留痕检查', undefined, {
        logDir: path.join(fileNotDir, 'logs'),
        now: new Date(2026, 8, 17),
      });
      const out = stderr.mock.calls.map((c) => String(c[0])).join('\n');
      expect(out).toContain('[loggerFlush]');
      expect(out).toContain('error-2026-09-17.log');
      // error 级有两个目标，两个都应各自失败并留痕（不是首个失败即短路）
      expect(out).toContain('combined-2026-09-17.log');
    } finally {
      stderr.mockRestore();
    }
  });

  test('即使落盘失败，返回值仍是渲染好的行（调用方契约不变）', () => {
    const stderr = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const line = flushLogsSync('error', '渲染仍须正确', undefined, {
        logDir: path.join(fileNotDir, 'logs'),
        now: new Date(2026, 8, 17),
      });
      expect(line).toContain('渲染仍须正确');
      expect(line).toMatch(/\[error\]/);
    } finally {
      stderr.mockRestore();
    }
  });

});
