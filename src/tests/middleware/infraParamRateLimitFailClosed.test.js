/**
 * ──────────────────────────────────────────────────────────────────────────
 * 本文件的定位（2026-09-20 补注，由变异审计批量补齐）
 *
 * 被测对象：基础设施机制：app.param 对子 Router 生效、限流覆盖根路径文档端点、fail-closed 契约单一声明
 * 守护的不变式：机制必须**真的被执行到**，而不是只检查配置对象长什么样
 * 可证伪性：变异实测（筛查 N=2）：杀 2/6
 *
 * 命名沿革：2026-09-20 由 `infraHardening.test.js` 更名。旧名里的
 *   Coverage / Gap / Hardening / Branch 说的是「当初为什么写它」（补覆盖率基线），
 *   **不是它的价值判据**；它能否挡住回归，由变异实测回答，不由文件名回答。
 *   旧名保留在本行，便于既往审计报告的 `grep 旧文件名` 仍能定位到本文件。
 * 依据：`deliverables/AGENT工作总账与待办-2026-09-21.md`（§2.9 测试资产 / §6 方法；原编号 §6-AW/AX/AY/AZ/BA 已随原台账删除，无法逐条映射）
 * ──────────────────────────────────────────────────────────────────────────
 */

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

    test('业务路由的非法 :id 在参数阶段就被拒（400 + 码化，不到 500）', async () => {
      // 【实测修正】原用例标题/注释称「未带令牌时 authenticate 先返回 401」——不成立。
      // router.param 回调注册在子 Router 上，执行早于路由级 authenticate：
      // 非法 :id 直接 400，合法 :id 才会走到 401（单独验证过两条分支）。
      // 断言点名前缀错误码：只断 400 时，「被别的 400 拦下」与「真的没走到 Mongoose」
      // 无法区分；而本用例的主张正是后者。
      const res = await request(app).get('/api/devices/not-an-objectid');
      expect(res.status).toBe(400);
      expect(res.body.errors?.errorCode).toBe('PARAM_MUST_BE_VALID_OBJECT_ID');
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

    /**
     * 临时启用 API 文档并创建应用实例。
     *
     * 为什么不用 jest.resetModules()：app 内部持有的 mongoose 实例会在
     * reset 后重建为**未连接**的新实例，每个请求都要等 10s buffering
     * 超时，用例直接被拖垮（实测）。而 ENABLE_API_DOCS 的读取点在
     * createApp() 内（app.js: `if (swagger.isDocsEnabled())`）、凭据读取点在 basicAuth
     * 请求期，二者都走 process.env —— 只需改写环境变量后重新 createApp() 即可。
     *
     * 注意：P2-26 用例调用过 jest.resetModules()，此后 require 到的 app 与
     * swagger 都是新副本（与文件顶部缓存的实例不同一），因此回调
     * 同时返回新副本的 swagger，供调用方操作真正生效的 docsLimiter 单例。
     */
    const withDocsEnabled = async (fn) => {
      const saved = {
        ENABLE_API_DOCS: process.env.ENABLE_API_DOCS,
        DOCS_USERNAME: process.env.DOCS_USERNAME,
        DOCS_PASSWORD: process.env.DOCS_PASSWORD,
      };
      process.env.ENABLE_API_DOCS = 'true';
      process.env.DOCS_USERNAME = 'infra-probe-user';
      process.env.DOCS_PASSWORD = 'infra-probe-password-long-enough';
      try {
        const { createApp } = require('../../app');
        const app = createApp();
        const freshSwagger = require('../../config/swagger');
        // docsLimiter 是 config/swagger.js 的模块级单例 → 本文件所有用例共用一个
        // 内存桶。「跑满配额验证 429」那条用例把桶打满后，后续用例的 /api-docs
        // 会从 200 变 429（固定顺序下恰好没人先跑满，所以一直隐身；
        // 换 --randomize 的 seed 即复现）。每次进入前先清一次自己的键。
        // keyGenerator 是 `api-docs:${req.ip}`，而 supertest 下 req.ip 的形态
        // 不唯一（::1 / ::ffff:127.0.0.1 / 127.0.0.1）→ 三种都清，不靠猜。
        for (const ip of ['::1', '::ffff:127.0.0.1', '127.0.0.1']) {
          if (typeof freshSwagger.docsLimiter?.resetKey === 'function') {
            await freshSwagger.docsLimiter.resetKey(`api-docs:${ip}`);
          }
        }
        return await fn(app, freshSwagger);
      } finally {
        for (const [k, v] of Object.entries(saved)) {
          if (v === undefined) delete process.env[k];
          else process.env[k] = v;
        }
      }
    };

    const DOCS_AUTH = `Basic ${Buffer.from(
      'infra-probe-user:infra-probe-password-long-enough'
    ).toString('base64')}`;

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

    test('模板确有内联 style，CSP 仅对 /api-docs 放行 unsafe-inline（L-5，真实响应头验证）', async () => {
      const html = swagger.renderDocsHtml();
      expect(html).toMatch(/<style[^>]*>/i);

      // 【本次改动改造：静态断言 → 行为断言】原用例匹配 security.js 源码里的
      // 正则片段——把条件判断改成恒真（对所有路径都放行 unsafe-inline）
      // 后，源码里的片段依然存在，断言照样绿。
      // 现直接读真实响应的 Content-Security-Policy 头（文档真实启用、带凭据 200）：
      //   /api-docs/*  → style-src 含 'unsafe-inline'（Swagger UI 自注入内联 style）
      //   其余路径     → style-src 为每请求 nonce，不含 'unsafe-inline'
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      require('../../models/TokenBlacklist');

      // 请求必须在环境变量生效窗口内发出（basicAuth 请求期读凭据）
      await withDocsEnabled(async (app) => {
        const docs = await request(app).get('/api-docs/').set('Authorization', DOCS_AUTH);
        expect(docs.status).toBe(200);
        const docsCsp = docs.headers['content-security-policy'];
        expect(docsCsp).toBeTruthy();
        expect(docsCsp).toMatch(/style-src [^;]*'unsafe-inline'/);

        const health = await request(app).get('/health');
        expect(health.status).toBe(200);
        const healthCsp = health.headers['content-security-policy'];
        expect(healthCsp).toBeTruthy();
        expect(healthCsp).not.toMatch(/'unsafe-inline'/);
        expect(healthCsp).toMatch(/style-src 'self' 'nonce-[A-Za-z0-9+/=]+'/);
      });
    });

    test('docsLimiter 已导出且为中间件函数', () => {
      expect(typeof swagger.docsLimiter).toBe('function');
    });

    test('/api-docs 限流早于 Basic Auth 挂载（用真实 429 判定顺序）', async () => {
      // 【本次改动改造：静态断言 → 行为断言】原用例比较 app.js 源码同一行内
      // docsLimiter 与 basicAuth 的字符位置——把两个中间件在运行时对调
      // 时源码文本不变，断言照样绿。
      //
      // 行为判据：凭据错误时 basicAuth 返回 401 并终止链。若限流器在 basicAuth
      // **之前**，计数照常累积，最终必出现 429；若在其之后，请求永远到不了
      // 限流器，无论请求多少次都只有 401、永无 429。
      //
      // 实现约束：此处**不能**用 jest.resetModules() 切换 ENABLE_API_DOCS。
      // 那会重建 mongoose 模块实例，而 app 内部持有的是新实例、处于未连接
      // 状态，每个请求都要等 10s buffering 超时（实测用例直接超时）。
      // 现改为直接改写 process.env 后重新 createApp()：app.js 的
      // isDocsEnabled() 与 basicAuth 都在运行期读 env，模块无需重载。
      const mongoose = require('mongoose');
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI);
      }
      require('../../models/TokenBlacklist');

      await withDocsEnabled(async (app, freshSwagger) => {
        // 同一 docsLimiter 单例的计数桶可能被本文件其它用例消耗
        // （如 CSP 用例的一次带凭据请求）。先复位，使「401 累积 → 429 截断」
        // 从零开始，避免残留计数造成假 429（复位失败时首请求即 429，
        // 下方 first.status 断言会直接变红）。
        await freshSwagger.docsLimiter.resetKey('api-docs:::ffff:127.0.0.1');

        // 未带凭据 → 401（证明 basicAuth 确实在链上，且计数桶已复位）
        const first = await request(app).get('/api-docs/');
        expect(first.status).toBe(401);

        // 反复请求：必须出现 429（限流在 basicAuth 之前才有此现象）
        let saw429 = false;
        let statuses = [];
        for (let i = 0; i < 80; i += 1) {
          const r = await request(app).get('/api-docs/');
          statuses.push(r.status);
          if (r.status === 429) {
            saw429 = true;
            break;
          }
          // 凭据缺失时，限流之前不应出现 401 以外的状态码
          expect(r.status).toBe(401);
        }
        expect(saw429).toBe(true);
        // 429 必须在至少一次 401 之后（首次就 429 = 桶没复位/顺序可疑）
        expect(statuses.length).toBeGreaterThan(1);

        // JSON 端点与 HTML 共用同一个桶（keyGenerator 按 IP），
        // 故此时它也必须已被限流覆盖——证明它同样挂在 docsLimiter 之后
        const jsonRes = await request(app).get('/api-docs.json');
        expect(jsonRes.status).toBe(429);
      });
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
