/**
 * 迁移目标库白名单必须与 destructiveGuard 同口径（全限定名 host:port/db 这一档）
 *
 * `scripts/destructiveGuard.js` 的 `assertApplyAllowed` 有两道后置收紧，都要调用方**主动传参**
 * 才生效：`host`（让白名单能写成 `127.0.0.1:27017/db`，把放行面收紧到指定主机）与
 * `isFallback`（禁止对"未设 MONGODB_URI 回退出来的库"做破坏性写）。
 * `migrate-mongo-config.js` 原先只传 `{scriptName, dbName, apply}` ⇒ 全仓其他 `--apply` 脚本
 * 都受这两道约束，唯独**迁移**这一条绕开了。绕开的两个方向都真实发作（实测见下），
 * 而迁移不是无害操作：`migrations/` 里有 `collMod` 改 `auditlogs` 的 TTL、`dropIndex`、
 * 全集合 `updateMany`——打错目标即改变审计留存窗口。
 *
 * 本文件只钉 `host` 这一档（无争议的一半）：
 *   ① 白名单已经是 `host/db` 且主机段命中 ⇒ 必须放行。修复前**红**：条目含 `/` 时比对用的
 *      `qualifiedHost` 取调用方传的 `host`，没传就是空串 ⇒ 永不命中 ⇒ 健康的收紧配置被误拒。
 *   ② 同样的条目但主机段不命中 ⇒ 必须中止。这条是 ① 的牙齿：只把 `host` 传下去而比对写错
 *      （比如整串小写比较、或忽略库名段大小写）都会让它转红。
 *   ③ 裸库名条目语义不变（向后兼容 `.env.example` 的写法）。
 *   ④ 拒绝时的提示不得教用户改成裸库名：原文案是 `正确用法：ALLOWED_SOURCE_DB=<dbName>`，
 *      在"条目本来就写了主机段"的场景里等于**主动建议把放行面从一台机器放宽到任意机器**——
 *      误拒的真正危害不在"这次没跑成"，而在运维为了跑成而放宽护栏。
 *
 * `isFallback` 那一档不在这里改：它与其他脚本的既定口径一致（回退库禁止 --apply），
 * 但本仓已有用例把"未配 MONGODB_URI 仍可迁移"断言成期望（另一条线的既有口径），
 * 两处必须同时改才有意义，故作为待决升级给使用方，见 deliverables 台账。
 */

const path = require('path');

const CONFIG = path.join(__dirname, '../../../migrate-mongo-config.js');

/**
 * 在受控 env 下加载迁移配置并求值 `mongodb.url`。
 * 空串表示"已设置但没配"：配置模块每次加载都会跑 `dotenv.config()`，删掉的键会被 .env 重新注入，
 * 而 resolveMongoUri 判"未配置"用的是 `.trim()` 后为空。
 * @param {{uri: string, allowed?: string}} env
 */
function evalUrl({ uri, allowed }) {
  const saved = {
    MONGODB_URI: process.env.MONGODB_URI,
    ALLOWED_SOURCE_DB: process.env.ALLOWED_SOURCE_DB,
    exitCode: process.exitCode,
  };
  const printed = [];
  const originals = { log: console.log, warn: console.warn, error: console.error };
  process.env.MONGODB_URI = uri;
  if (allowed === undefined) delete process.env.ALLOWED_SOURCE_DB;
  else process.env.ALLOWED_SOURCE_DB = allowed;
  // 护栏走 process.exitCode（不是 process.exit），不还原会让整个 jest 进程带 2 退出
  process.exitCode = 0;
  console.log = (...a) => printed.push(a.join(' '));
  console.warn = (...a) => printed.push(a.join(' '));
  console.error = (...a) => printed.push(a.join(' '));
  try {
    jest.resetModules();
    const cfg = require(CONFIG);
    try {
      return { value: cfg.mongodb.url, error: '', printed: printed.join('\n') };
    } catch (err) {
      return { value: undefined, error: String(err.message), printed: printed.join('\n') };
    }
  } finally {
    Object.assign(console, originals);
    Object.entries(saved).forEach(([k, v]) => {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    });
  }
}

const DB = 'zzqB_migrate_db';
const URI = `mongodb://127.0.0.1:27017/${DB}`;

describe('迁移目标库白名单与护栏同口径', () => {
  test('① 白名单写成 host:port/db 且主机段命中 ⇒ 放行并交出连接串', () => {
    const r = evalUrl({ uri: URI, allowed: `127.0.0.1:27017/${DB}` });
    expect(r.error).toBe('');
    expect(r.value).toBe(URI);
  });

  test('② 同样的全限定条目但主机段不命中 ⇒ 中止（证明 host 真被比对）', () => {
    const r = evalUrl({ uri: URI, allowed: `10.20.30.40:27017/${DB}` });
    expect(r.value).toBeUndefined();
    expect(r.error).toContain('ALLOWED_SOURCE_DB 白名单校验');
  });

  test('③ 裸库名条目仍然放行（收紧形态不能破坏既有写法）', () => {
    const r = evalUrl({ uri: URI, allowed: `other_db,${DB}` });
    expect(r.error).toBe('');
    expect(r.value).toBe(URI);
  });

  test('④ 主机段不命中时的提示必须给收紧形态，不得建议裸库名', () => {
    const r = evalUrl({ uri: URI, allowed: `10.20.30.40:27017/${DB}` });
    // 裸库名提示等于让运维把"只放行一台机器"改成"放行任何机器上的同名库"
    expect(r.error).not.toContain(`ALLOWED_SOURCE_DB=${DB}`);
    expect(r.error).toContain(`ALLOWED_SOURCE_DB=127.0.0.1:27017/${DB}`);
    // 未设白名单那段（只是建议，不拒绝）也必须给同样的收紧形态：
    // 照提示配出来的白名单不能比本次目标更宽
    const w = evalUrl({ uri: URI });
    expect(w.error).toBe('');
    expect(w.printed).toContain(`ALLOWED_SOURCE_DB=127.0.0.1:27017/${DB}`);
    expect(w.printed).not.toContain(`ALLOWED_SOURCE_DB=${DB} `);
  });

  test('⑤ 前提自证：本文件判的是真实代码路径，不是注释', () => {
    const fs = require('fs');
    const src = fs.readFileSync(CONFIG, 'utf8').replace(/\r\n/g, '\n');
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    // 修复的本体：host 必须出现在传给 assertApplyAllowed 的实参里
    expect(code).toMatch(/assertApplyAllowed\(\s*\{[^}]*\bhost\b[^}]*\}/);
    // 且没有把回退库这一档偷偷改掉（那是另一处待决）
    expect(code).not.toMatch(/assertApplyAllowed\(\s*\{[^}]*isFallback[^}]*\}/);
  });
});
