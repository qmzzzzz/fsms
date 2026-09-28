/**
 * src/utils/constants.js 不得再养"零引用的枚举副本"
 *
 * 为什么值得做成门禁：这个文件原先导出 14 个枚举，其中 10 个全仓零引用，
 * 而它们不是无害的死码——同一个业务枚举存在两份声明时，第二份只会 drift 不会被同步：
 *   - ALARM_LEVEL 写的是 low/medium/high/critical，模型侧 models/FireAlarm.js 的
 *     level 实为 info/warning/critical/emergency：拿"集中管理的常量"去做校验，
 *     合法值被判非法、非法值被放行，而且两边各自都"看起来是事实来源"；
 *   - INSPECTION_STATUS 缺 overdue，INSPECTION_RESULT 缺 partial（同样已经漂了）。
 *
 * 判据分工（少一条就留假绿）：
 *   1. 扫描器自检：真引用要数到、注释里的提及不能数到（否则"注释即使用"恒绿）、
 *      含 `//` 的字符串（URL）不能把整行吃掉导致漏数；
 *   2. 规模下界：扫不到足够多的生产文件时，"零引用"结论是空的；
 *   3. 主判据：每个导出名都要有至少一个生产文件引用它。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../../..');
const SELF = 'src/utils/constants.js';
const PROD_DIRS = ['src', 'scripts', 'migrations'];

/**
 * 去掉块注释与行注释，但不吃 `http://` 这种字符串里的双斜杠。
 * 不做注释剥离的话，文件头写一句"与 DEVICE_TYPE 对齐"就算"被引用了"。
 */
function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** 生产源码文件（排除 src/tests 与常量模块自身） */
function collectProdFiles(dir, out = []) {
  for (const entry of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'coverage') continue;
      if (rel === 'src/tests') continue;
      collectProdFiles(rel, out);
    } else if (entry.name.endsWith('.js') && rel !== SELF) {
      out.push(rel);
    }
  }
  return out;
}

const PROD_FILES = PROD_DIRS.flatMap((d) => collectProdFiles(d));
const PROD_TEXTS = PROD_FILES.map((rel) =>
  stripComments(fs.readFileSync(path.join(ROOT, rel), 'utf8'))
);

const exported = require('../../utils/constants');

function refCount(name) {
  const re = new RegExp(`\\b${name}\\b`);
  return PROD_TEXTS.filter((t) => re.test(t)).length;
}

describe('constants.js 导出的存活性与扫描器可信度', () => {
  test('前提自证：扫描器数得到真引用、数不到注释里的提及', () => {
    const re = /\bDEVICE_TYPE\b/;
    // 真引用
    expect(re.test(stripComments("const { DEVICE_TYPE } = require('../utils/constants');"))).toBe(
      true
    );
    // 行注释 / 块注释里的同名提及都不算引用
    expect(re.test(stripComments('// 与 DEVICE_TYPE 对齐'))).toBe(false);
    expect(re.test(stripComments('/* DEVICE_TYPE */'))).toBe(false);
    // 反向陷阱：带 URL 的行不能被当成注释整行吃掉，否则同行的真引用会漏数
    expect(
      re.test(
        stripComments("const url = 'http://example.com'; const { DEVICE_TYPE } = require('.');")
      )
    ).toBe(true);
  });

  test('规模下界：确实在扫生产源码，而不是空集合让判据恒真', () => {
    expect(PROD_FILES.length).toBeGreaterThanOrEqual(150);
    expect(PROD_FILES).toEqual(expect.arrayContaining(['src/routes/deviceRoutes.js']));
    // 常量模块自身必须被排除，否则"自己引用自己"就是第一个假绿
    expect(PROD_FILES).not.toContain(SELF);
  });

  test('每个导出枚举都至少被一个生产文件使用（零引用即死码，必须删除）', () => {
    const keys = Object.keys(exported);
    expect(keys.length).toBeGreaterThanOrEqual(1);
    const dead = keys.filter((k) => refCount(k) === 0);
    expect(dead).toEqual([]);
  });
});
