/**
 * 批次C 基础设施类修复回归（P2-25/26/28/29/30 + P2-27 脚本门禁）
 *
 * 这批缺陷的共同点是「看起来配好了、实际没生效」：
 * - app.param 注册了却对子 Router 不生效（Express 4 语义）
 * - 限流器配好了却没覆盖到根路径的文档端点
 * - 报废守卫式的 fail-closed 契约在同一文件里两个函数各写一套
 * 因此断言重点是「机制真的被执行到」，而非只检查配置对象长什么样。
 */

const fs = require('fs');
const path = require('path');
const request = require('supertest');
const mongoose = require('mongoose');

const REPO_ROOT = path.resolve(__dirname, '../../..');

describe('批次C 基础设施加固回归', () => {
  // ================= P2-25 :id 参数校验真正生效 =================
  describe('P2-25 子 Router 级 ObjectId 参数校验', () => {
    let app;

    beforeAll(async () => {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      require('../../models/TokenBlacklist');
      const { createApp } = require('../../app');
      app = createApp();
    });

    afterAll(async () => {
      if (mongoose.connection.readyState !== 0) {
        await mongoose.connection.close();
      }
    });

    test('applyObjectIdParams 在子 Router 上确实注册了回调', () => {
      const express = require('express');
      const { applyObjectIdParams } = require('../../middleware/validateObjectId');
      const router = express.Router();
      applyObjectIdParams(router);
      // Express 4 把 param 回调存在 router.params[name]
      expect(Object.keys(router.params || {})).toEqual(expect.arrayContaining(['id', 'userId']));
    });

    test('重复注册幂等（createApp 多次调用不会叠加回调）', () => {
      const express = require('express');
      const { applyObjectIdParams } = require('../../middleware/validateObjectId');
      const router = express.Router();
      applyObjectIdParams(router);
      applyObjectIdParams(router);
      applyObjectIdParams(router);
      expect(router.params.id).toHaveLength(1);
    });

    test('app.param 对子 Router 无效——这正是原实现失效的根因', async () => {
      const express = require('express');
      const probe = express();
      const sub = express.Router();
      let appLevelHits = 0;
      probe.param('id', (req, res, next) => {
        appLevelHits += 1;
        next();
      });
      sub.get('/:id', (req, res) => res.json({ ok: true }));
      probe.use('/sub', sub);

      await request(probe).get('/sub/not-an-objectid');
      expect(appLevelHits).toBe(0); // 子 Router 完全绕过 app 级 param

      // 对照：直挂 app 的路由会命中
      probe.get('/direct/:id', (req, res) => res.json({ ok: true }));
      await request(probe).get('/direct/not-an-objectid');
      expect(appLevelHits).toBe(1);
    });

    test('业务路由的非法 :id 在参数阶段就被拒（未认证时先被 401 拦下，不到 500）', async () => {
      // 未带令牌时 authenticate 会先返回 401；关键是不应出现 CastError→500
      const res = await request(app).get('/api/devices/not-an-objectid');
      expect([400, 401]).toContain(res.status);
      expect(res.status).not.toBe(500);
    });
  });

  // ================= P2-26 登出 fail-closed =================
  describe('P2-26 blacklistToken fail-closed 契约', () => {
    test('普通持久化失败向上抛错并带明确错误码', async () => {
      jest.resetModules();
      jest.doMock('../../models/TokenBlacklist', () => ({
        findOneAndUpdate: jest.fn().mockRejectedValue(new Error('db down')),
        create: jest.fn(),
      }));
      const { blacklistToken } = require('../../middleware/tokenBlacklist');
      await expect(
        blacklistToken('tok', Math.floor(Date.now() / 1000) + 3600)
      ).rejects.toMatchObject({ code: 'BLACKLIST_PERSIST_FAILED' });
      jest.dontMock('../../models/TokenBlacklist');
      jest.resetModules();
    });

    test('LOGOUT_REVOKE_FAILED 错误码为 5xx（前端据此保留令牌并重试）', () => {
      const { ERROR_CODES } = require('../../utils/errorCodes');
      const entry = ERROR_CODES.LOGOUT_REVOKE_FAILED;
      expect(entry).toBeDefined();
      expect(entry.status).toBeGreaterThanOrEqual(500);
      // 文案必须让用户知道令牌仍有效，否则等同于 fail-open 的体验
      expect(entry.message).toContain('仍然有效');
    });
  });

  // ================= P2-27 运维脚本门禁 =================
  describe('P2-27 运维脚本安全约定', () => {
    const readScript = (name) => fs.readFileSync(path.join(REPO_ROOT, 'scripts', name), 'utf8');

    /**
     * 剥离注释行后再断言。
     * 修复说明里会原样引用被替换掉的危险写法（如 `--uri=`、`$? -eq 0`）作为对照，
     * 若直接对全文匹配，注释本身就会让测试误报——断言必须只看可执行代码。
     */
    const codeOf = (name) =>
      readScript(name)
        .split('\n')
        .filter((l) => !/^\s*#/.test(l))
        .join('\n');

    test('backup-mongo.sh 不把含凭据的 URI 放到命令行', () => {
      const code = codeOf('backup-mongo.sh');
      expect(code).not.toMatch(/mongodump[^\n]*--uri=/);
      expect(code).toMatch(/mongodump[^\n]*--config=/);
      // 凭据文件必须限权并在退出时清理
      expect(code).toContain('umask 077');
      expect(code).toMatch(/chmod 600/);
      expect(code).toMatch(/trap cleanup EXIT/);
    });

    test('restore-mongo.sh 有确认门禁且不再含死代码', () => {
      const code = codeOf('restore-mongo.sh');
      expect(code).not.toMatch(/mongorestore[^\n]*--uri=/);
      expect(code).toMatch(/RESTORE_CONFIRM/);
      // set -e 下 `if [ $? -eq 0 ]` 的 else 分支永不执行，是误导运维的死代码
      expect(code).not.toMatch(/\$\?\s*-eq\s*0/);
      // --drop 必须显式开启
      expect(code).toMatch(/RESTORE_DROP/);
      expect(code).toMatch(/chmod 600/);
      expect(code).toMatch(/trap cleanup EXIT/);
    });

    test('恢复门禁的确认值必须与目标库名比对（而非任意非空值即放行）', () => {
      const code = codeOf('restore-mongo.sh');
      // 实测行为：RESTORE_CONFIRM=wrong_db 被拒、=fire_safety 才放行。
      // 这里锁定比对目标是 TARGET_DB，防止后续改成 `-n "$RESTORE_CONFIRM"`
      // 这类"有值就行"的弱校验（那样 CI 里写个 y 就能覆盖生产）
      expect(code).toMatch(/"\$\{RESTORE_CONFIRM:-\}"\s*!=\s*"\$TARGET_DB"/);
    });

    test('两个脚本都启用严格模式（未定义变量即失败）', () => {
      for (const name of ['backup-mongo.sh', 'restore-mongo.sh']) {
        expect(readScript(name)).toMatch(/set -euo pipefail/);
      }
    });

    test('fix-token-blacklist-index.js 默认演练，需 --apply 才动手', () => {
      const js = readScript('fix-token-blacklist-index.js');
      expect(js).toMatch(/--apply/);
      expect(js).toMatch(/DRY-RUN|演练/);
    });

    test('verify-audit-chain.js 不接受命令行传连接串', () => {
      const js = readScript('verify-audit-chain.js');
      expect(js).toMatch(/process\.env\.MONGODB_URI/);
      // 不得从位置参数取 URI（会进 ps）
      expect(js).not.toMatch(/process\.argv\[2\]\s*\|\|\s*process\.env\.MONGODB_URI/);
    });
  });

  // ================= P2-28 dev-vite.cmd =================
  describe('P2-28 dev-vite.cmd 文件完整性', () => {
    const cmdPath = path.join(REPO_ROOT, 'dev-vite.cmd');

    test('不再是单行文件（原损坏形态）', () => {
      const raw = fs.readFileSync(cmdPath, 'utf8');
      const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
      expect(lines.length).toBeGreaterThan(5);
    });

    test('使用 CRLF 换行（cmd.exe 对 LF-only 的多行脚本行为不可靠）', () => {
      const raw = fs.readFileSync(cmdPath, 'latin1');
      expect(raw).toContain('\r\n');
      expect(/[^\r]\n/.test(raw)).toBe(false);
    });

    test('watch 循环三要素齐备（标签、启动、跳回）', () => {
      const raw = fs.readFileSync(cmdPath, 'utf8');
      expect(raw).toMatch(/^:loop\s*$/m);
      expect(raw).toMatch(/npx vite/);
      expect(raw).toMatch(/^goto loop\s*$/m);
    });

    test('仅含 ASCII 字符（.cmd 按控制台代码页读取，中文会乱码）', () => {
      const raw = fs.readFileSync(cmdPath, 'utf8');
      // eslint-disable-next-line no-control-regex
      expect(/[^\x00-\x7F]/.test(raw)).toBe(false);
    });
  });

  // ================= P2-29 / P2-30 Swagger =================
  describe('P2-29/30 API 文档出口治理', () => {
    const swagger = require('../../config/swagger');

    test('渲染模板不含内联 script（否则被 script-src self 拦成白屏）', () => {
      const html = swagger.renderDocsHtml();
      expect(html.length).toBeGreaterThan(0);
      const inlineScripts = html.match(/<script(?![^>]*\bsrc=)[^>]*>/gi) || [];
      expect(inlineScripts).toHaveLength(0);
    });

    test('所有脚本均为同源相对路径（不依赖外部 CDN）', () => {
      const html = swagger.renderDocsHtml();
      const srcs = [...html.matchAll(/<script[^>]*\bsrc=["']([^"']+)["']/gi)].map((m) => m[1]);
      expect(srcs.length).toBeGreaterThan(0);
      for (const src of srcs) {
        expect(src.startsWith('./') || src.startsWith('/')).toBe(true);
      }
    });

    test('模板确有内联 style，CSP 仅对 /api-docs 放行 unsafe-inline（L-5）', () => {
      const html = swagger.renderDocsHtml();
      expect(html).toMatch(/<style[^>]*>/i);
      // 与 security.js 的实现保持一致，避免只改一处：
      // 主 CSP 走每请求 nonce，仅文档路径条件式放行 'unsafe-inline'
      const security = fs.readFileSync(path.join(REPO_ROOT, 'src/middleware/security.js'), 'utf8');
      expect(security).toMatch(/'nonce-\$\{res\.locals\.cspNonce\}'/);
      expect(security).toMatch(/isSwaggerDocsPath\(req\)\s*\?\s*"'unsafe-inline'"/);
      // 全局常量里不得再出现无条件 'unsafe-inline' 的 style-src
      expect(security).not.toMatch(/'style-src':\s*\["'self'",\s*"'unsafe-inline'"\]/);
    });

    test('docsLimiter 已导出且为中间件函数', () => {
      expect(typeof swagger.docsLimiter).toBe('function');
    });

    test('/api-docs 限流早于 Basic Auth 挂载（顺序颠倒则限流失去意义）', () => {
      const appSrc = fs.readFileSync(path.join(REPO_ROOT, 'src/app.js'), 'utf8');
      const line = appSrc.split('\n').find((l) => l.includes("app.use('/api-docs'"));
      expect(line).toBeTruthy();
      expect(line.indexOf('docsLimiter')).toBeLessThan(line.indexOf('basicAuth'));
      // JSON 端点同样受限流覆盖
      const jsonLine = appSrc.split('\n').find((l) => l.includes("'/api-docs.json'"));
      expect(jsonLine).toContain('docsLimiter');
    });

    test('超出配额后返回 429（真实请求验证限流生效）', async () => {
      const express = require('express');
      const probe = express();
      // 用独立 app 验证限流器本身，避免污染主 app 的计数桶
      probe.use('/api-docs', swagger.docsLimiter, (req, res) => res.send('ok'));

      const max = Number(process.env.DOCS_RATE_LIMIT_MAX) || 30;
      let sawTooMany = false;
      for (let i = 0; i < max + 5; i += 1) {
        const res = await request(probe).get('/api-docs/');
        if (res.status === 429) {
          sawTooMany = true;
          break;
        }
      }
      expect(sawTooMany).toBe(true);
    });
  });
});
