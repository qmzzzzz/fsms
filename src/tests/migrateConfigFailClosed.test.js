'use strict';

/**
 * （2026-09-19）：migrate-mongo-config.js 的目标库判据
 *
 * 原实现：`url: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/fire_safety_db'`
 * —— 迁移（up/down 会改数据结构）在没有显式连接串时**静默**打到本机默认库，
 * 而且那份回退串把 destructiveGuard 里已有的唯一事实来源又抄了一遍。
 *
 * 现口径（三条，逐条可证伪）：
 *  1) 回退不再静默：走 resolveMongoUri，未设 MONGODB_URI 会打印来源；
 *  2) 每次连库都回显目标库名；设了 ALLOWED_SOURCE_DB 就按它拒绝越界库；
 *  3) 判据惰性求值 —— `migrate:create` 不碰数据库，不该被目标库判据挡住。
 * 未设白名单时**不拦**是刻意选择：scripts/deploy.js 在应用容器里跑 `migrate-mongo up`，
 * 那里由 secret 文件下发连接串、没有也不需要该变量；在此 fail-closed 会把每次生产部署
 * 变成"必须新增必配项"的破坏性变更。该权衡已作为待决项升级给使用方。
 */

const fs = require('fs');
const path = require('path');

const CONFIG = path.join(__dirname, '../../migrate-mongo-config.js');
const src = fs.readFileSync(CONFIG, 'utf8').replace(/\r\n/g, '\n');
// 文本断言一律在剥掉注释的代码视图上做（本仓同类假绿已发作过两次）
const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

/**
 * 在受控 env 下加载配置并求值 mongodb.url，收集打印输出。
 * @param {{uri?: string, allowed?: string}} env  uri=undefined 表示"没配 MONGODB_URI"
 */
function evalUrl({ uri, allowed }) {
  const savedUri = process.env.MONGODB_URI;
  const savedAllowed = process.env.ALLOWED_SOURCE_DB;
  const savedExitCode = process.exitCode;
  const printed = [];
  const originals = { log: console.log, warn: console.warn, error: console.error };
  // 空串 = "已设置但没配"：dotenv 不会覆盖已存在的键，删键会被 .env 重新注入
  process.env.MONGODB_URI = uri === undefined ? '' : uri;
  if (allowed === undefined) delete process.env.ALLOWED_SOURCE_DB;
  else process.env.ALLOWED_SOURCE_DB = allowed;
  // 护栏走的是 process.exitCode（不是 process.exit），不还原会让整个 jest 进程带 2 退出
  process.exitCode = 0;
  console.log = (...a) => printed.push(a.join(' '));
  console.warn = (...a) => printed.push(a.join(' '));
  console.error = (...a) => printed.push(a.join(' '));
  try {
    jest.resetModules();
    const cfg = require(CONFIG);
    try {
      return { value: cfg.mongodb.url, printed: printed.join('\n') };
    } catch (err) {
      return { error: err.message, printed: printed.join('\n') };
    }
  } finally {
    Object.assign(console, originals);
    if (savedUri === undefined) delete process.env.MONGODB_URI;
    else process.env.MONGODB_URI = savedUri;
    if (savedAllowed === undefined) delete process.env.ALLOWED_SOURCE_DB;
    else process.env.ALLOWED_SOURCE_DB = savedAllowed;
    process.exitCode = savedExitCode;
  }
}

describe('迁移目标库判据', () => {
  test('加载配置本身不碰数据库：migrate:create 不该被目标库判据挡住', () => {
    jest.resetModules();
    expect(() => require(CONFIG)).not.toThrow();
    jest.resetModules();
    const cfg = require(CONFIG);
    // 前提自证：url 是访问器属性而非数据属性，所以"没抛错"不是因为它被提前算好了
    const prop = Object.getOwnPropertyDescriptor(cfg.mongodb, 'url');
    expect(typeof prop.get).toBe('function');
    expect(prop.value).toBeUndefined();
    // migrate-mongo 的 config.read() 只做顶层展开（{...config}），不会触发内层 getter
    const spread = { ...cfg };
    expect(typeof spread.mongodb).toBe('object');
    expect(spread.migrationsDir).toBe('migrations');
  });

  test('设了 ALLOWED_SOURCE_DB 而目标库不命中 ⇒ 拒绝交出连接串', () => {
    const r = evalUrl({
      uri: 'mongodb://127.0.0.1:27017/drill',
      allowed: 'other_db',
    });
    expect(r.value).toBeUndefined();
    expect(r.error).toContain('ALLOWED_SOURCE_DB 白名单校验');
    expect(r.error).toContain('drill');
    expect(r.error).toContain('npm run migrate:up');
  });

  test('白名单命中 ⇒ 原样交出 MONGODB_URI，并回显目标库名', () => {
    const r = evalUrl({
      uri: 'mongodb://127.0.0.1:27017/drill',
      allowed: 'drill,other_ok',
    });
    expect(r.error).toBeUndefined();
    expect(r.value).toBe('mongodb://127.0.0.1:27017/drill');
    expect(r.printed).toContain('迁移目标库：drill');
    // 命中白名单时不该再念"未设置白名单"那段
    expect(r.printed).not.toContain('不做白名单校验');
  });

  test('未设白名单 ⇒ 放行但必须说清楚（这是刻意的宽松，见文件头权衡）', () => {
    const r = evalUrl({ uri: 'mongodb://127.0.0.1:27017/drill' });
    expect(r.error).toBeUndefined();
    expect(r.value).toBe('mongodb://127.0.0.1:27017/drill');
    expect(r.printed).toContain('不做白名单校验');
    expect(r.printed).toContain('迁移目标库：drill');
  });

  test('没配 MONGODB_URI ⇒ 仍然可用，但回退不得静默', () => {
    const r = evalUrl({ uri: undefined, allowed: 'fire_safety_db' });
    expect(r.error).toBeUndefined();
    expect(r.value).toBe('mongodb://127.0.0.1:27017/fire_safety_db');
    // 旧实现这里一个字的提示都没有；现在来源必须出现在输出里
    expect(r.printed).toContain('回退到本地默认库');
    expect(r.printed).toContain('来自本地默认库回退');
    const r2 = evalUrl({ uri: undefined });
    expect(r2.printed).toContain('回退到本地默认库');
    expect(r2.value).toBe('mongodb://127.0.0.1:27017/fire_safety_db');
  });

  test('硬编码回退串已从这个文件消失（唯一事实来源在 destructiveGuard）', () => {
    expect(code).not.toContain('mongodb://127.0.0.1:27017');
    expect(code).toContain("require('./scripts/destructiveGuard')");
    expect(code).toContain('resolveMongoUri');
    // 负向自证：判据有牙齿——那串本地库地址在文件里只剩注释这一处
    expect(src.match(/mongodb:\/\/127\.0\.0\.1:27017/g)).toHaveLength(1);
  });

  test('部署路径不受影响：deploy.js 仍按容器内 status + up 两步走', () => {
    const deploy = fs
      .readFileSync(path.join(__dirname, '../../scripts/deploy.js'), 'utf8')
      .replace(/\r\n/g, '\n');
    // 前提自证：这条用例的存在理由就是"部署会在容器里跑 migrate-mongo up"，
    // 哪天部署改用别的迁移方式，上面那条"未设白名单不拦"的权衡就该重新评估
    expect(deploy).toContain("run('docker', [...migrateArgv, 'up'])");
    expect(deploy).toContain('node_modules/.bin/migrate-mongo');
  });
});
