/**
 * append-only 护栏加固回归（P1-32）
 *
 * 审计报告 §3.6 的两条反面结论：
 *   1. `models/AuditLog.js` **无条件导出** `_setAppendOnlyEnforced`——任何拿到模型
 *      对象的生产代码都能在运行期把防篡改护栏关掉（全仓无生产调用点，但门不该存在）；
 *   2. `models/auditLogHooks.js` 的 `bypassAppendOnly` 接受**任意真值**即放行，
 *      等于给 9 类写入口留了一个"传个字段就绕过"的后门。
 *
 * 修复后的契约（本文件即该契约的可执行规格）：
 *   - `_setAppendOnlyEnforced` 仅在 NODE_ENV === 'test' 时挂载；生产环境为 undefined。
 *   - `bypassAppendOnly` 仅在「测试环境 **且** 显式传入布尔 true」时放行；
 *     未传 / false / 非布尔（'true'、1）/ 生产环境一律拦截。
 *   - 正常写入路径（create / insertMany）不受任何影响（不经过该前置钩子）。
 *
 * 环境切换方式：`NODE_ENV` 是进程级变量，且钩子读的是**调用时刻**的值
 * （`process.env.NODE_ENV === 'test'` 在每次查询时求值，不是模块加载期快照），
 * 因此可在同一进程内用 try/finally 临时切换（同 tests/config/docsAccess.test.js 的写法）。
 *
 * 注意：不得用 `jest.resetModules()` 重载模型——同一 mongoose 实例上重复
 * `mongoose.model('AuditLog', ...)` 会抛 OverwriteModelError。
 */

const mongoose = require('mongoose');

describe('AuditLog append-only 护栏加固（P1-32）', () => {
  let AuditLog;
  const stamp = `p1l32_${Date.now().toString(36)}`;
  const withNodeEnv = async (value, fn) => {
    const saved = process.env.NODE_ENV;
    process.env.NODE_ENV = value;
    try {
      return await fn();
    } finally {
      process.env.NODE_ENV = saved;
    }
  };

  beforeAll(async () => {
    AuditLog = require('../../models/AuditLog');
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI);
    }
  });

  afterAll(async () => {
    if (mongoose.connection.readyState !== 0) {
      await AuditLog.deleteMany({ username: stamp }, { bypassAppendOnly: true }).catch(() => {});
      await mongoose.connection.close();
    }
  });

  describe('生产环境（NODE_ENV=production）', () => {
    test('6 类篡改入口 + deleteMany 全部被拒（报告 §3.6 的正面结论不得退化）', async () => {
      await withNodeEnv('production', async () => {
        const attempts = {
          updateOne: () => AuditLog.updateOne({ username: stamp }, { $set: { action: 'x' } }),
          updateMany: () => AuditLog.updateMany({ username: stamp }, { $set: { action: 'x' } }),
          deleteOne: () => AuditLog.deleteOne({ username: stamp }),
          deleteMany: () => AuditLog.deleteMany({ username: stamp }),
          replaceOne: () => AuditLog.replaceOne({ username: stamp }, { action: 'x' }),
          findOneAndUpdate: () =>
            AuditLog.findOneAndUpdate({ username: stamp }, { $set: { action: 'x' } }),
          findOneAndDelete: () => AuditLog.findOneAndDelete({ username: stamp }),
          findOneAndReplace: () => AuditLog.findOneAndReplace({ username: stamp }, { action: 'x' }),
          bulkWrite: () =>
            AuditLog.bulkWrite([
              { updateOne: { filter: { username: stamp }, update: { $set: { action: 'x' } } } },
            ]),
        };
        for (const run of Object.values(attempts)) {
          await expect(run()).rejects.toThrow('审计日志为 append-only，禁止修改/删除');
        }
      });
    });

    test('bypassAppendOnly: true 在生产环境**不再**放行', async () => {
      await withNodeEnv('production', async () => {
        await expect(
          AuditLog.deleteMany({ username: stamp }, { bypassAppendOnly: true })
        ).rejects.toThrow('审计日志为 append-only，禁止修改/删除');
        await expect(
          AuditLog.updateOne({ username: stamp }, { $set: { a: 1 } }, { bypassAppendOnly: true })
        ).rejects.toThrow('审计日志为 append-only，禁止修改/删除');
      });
    });

    test('_setAppendOnlyEnforced 受环境门控：生产环境调用不产生任何效果（双保险）', async () => {
      // 条件导出在模块加载期求值，加载时的 NODE_ENV 由 jest setupFiles 设为 'test'
      // ——故此处验证的是「挂载受环境门控」这一事实：符号存在的前提是加载期
      // NODE_ENV === 'test'。子进程探针单独验证生产环境的实际形态（下方用例）。
      expect(typeof AuditLog._setAppendOnlyEnforced).toBe('function');
      // 关键：即便拿到该函数，在生产环境调用也不产生任何效果（双保险）
      await withNodeEnv('production', async () => {
        AuditLog._setAppendOnlyEnforced(false);
        await expect(AuditLog.deleteMany({ username: stamp })).rejects.toThrow(
          '审计日志为 append-only，禁止修改/删除'
        );
      });
    });
  });

  describe('测试环境（NODE_ENV=test）', () => {
    test('bypassAppendOnly 仅接受布尔 true：非布尔/缺省一律拦截', async () => {
      await withNodeEnv('test', async () => {
        for (const bad of [undefined, false, 'true', 1, 'yes', {}]) {
          await expect(
            AuditLog.deleteMany({ username: stamp }, { bypassAppendOnly: bad })
          ).rejects.toThrow('审计日志为 append-only，禁止修改/删除');
        }
        // 显式布尔 true 放行（测试清理依赖此契约）
        await expect(
          AuditLog.deleteMany({ username: stamp }, { bypassAppendOnly: true })
        ).resolves.toBeDefined();
      });
    });

    test('正常写入路径不受护栏影响（create 与 insertMany 均放行）', async () => {
      await withNodeEnv('test', async () => {
        const doc = await AuditLog.create({
          action: 'p1l32_probe',
          category: 'system',
          username: stamp,
          success: true,
        });
        expect(doc._id).toBeTruthy();
        const many = await AuditLog.insertMany(
          [
            { action: 'p1l32_probe', category: 'system', username: stamp },
            { action: 'p1l32_probe', category: 'system', username: stamp },
          ],
          { ordered: false }
        );
        expect(many).toHaveLength(2);
      });
    });
  });

  describe('生产环境子进程探针（模块加载期 NODE_ENV 的真实形态）', () => {
    test('NODE_ENV=production 加载模型 → 无 _setAppendOnlyEnforced 且写入被拒', () => {
      const { execFileSync } = require('child_process');
      const path = require('path');
      const repoRoot = path.resolve(__dirname, '../../..');
      const probe = [
        "process.env.NODE_ENV = 'production';",
        "process.env.MONGODB_URI = 'mongodb://127.0.0.1:1/none';",
        "const AuditLog = require('./src/models/AuditLog');",
        '(async () => {',
        "  const out = ['typeof=' + typeof AuditLog._setAppendOnlyEnforced];",
        '  try {',
        '    await AuditLog.deleteMany({}, { bypassAppendOnly: true });',
        "    out.push('deleteMany=RESOLVED');",
        '  } catch (e) {',
        "    out.push('deleteMany=REJECTED:' + e.message);",
        '  }',
        "  process.stdout.write(out.join('|'));",
        '})();',
      ].join('\n');
      const stdout = execFileSync(process.execPath, ['-e', probe], {
        cwd: repoRoot,
        encoding: 'utf8',
        env: { ...process.env, NODE_ENV: 'production' },
      });
      expect(stdout).toContain('typeof=undefined');
      expect(stdout).toContain('deleteMany=REJECTED:审计日志为 append-only，禁止修改/删除');
    });
  });
});
