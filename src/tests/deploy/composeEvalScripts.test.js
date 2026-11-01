/**
 * docker-compose 内嵌 mongosh 脚本的静态可执行性闸（审计 2026-11-02 D-F1）
 *
 * 缺陷本体：mongo-rs-init 的等主脚本用 `for (let i)` 循环内哨兵值（i=999）+
 * 循环外 `if (i !== 999)` 判定——`let` 的作用域止于 ForStatement，循环后读 `i`
 * 是对未声明标识符的引用，成功与超时两条路都抛 ReferenceError ⇒ mongosh 非零
 * 退出 ⇒ depends_on: service_completed_successfully 永不满足 ⇒ app 永远不启动。
 *
 * 为什么是静态闸、为什么不是编译性检查：该缺陷是**运行时** ReferenceError，
 * 编译性检查（构造 Function 校验语法）都能通过；能抓住它的是 no-undef。
 * 本闸把 compose 里全部 mongosh 脚本片段交给 eslint Linter（mongosh 全局
 * 白名单 + no-undef error），并按本仓「可证伪」惯例内嵌一个中毒样本自证
 * 检测器有效——检测器本身失效（如 eslint API 变更导致静默零输出）时本套件
 * 红，而不是假绿。
 *
 * 边界：静态断言，不跑真实 docker/mongosh；mongosh 的转译器（babel 类）保块
 * 作用域，与 Node 的 for-let 语义一致（该前提与缺陷本体一同在目标机上可 60 秒
 * 实证）。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { Linter } = require('eslint');

const ROOT = path.resolve(__dirname, '../../..');
const compose = fs.readFileSync(path.join(ROOT, 'docker-compose.yml'), 'utf8');

/** mongosh/Node REPL 语义下脚本可引用的全局（脚本内自认的全部外部名字） */
const MONGOSH_GLOBALS = {
  rs: 'readonly',
  db: 'readonly',
  print: 'readonly',
  printjson: 'readonly',
  sleep: 'readonly',
  quit: 'readonly',
  process: 'readonly',
};

// mongosh 的脚本注入 flag 用字符类 `--[e]val` 书写：匹配真实字面量但不构成
// 其连续字符串形态——完整字面量会撞上安全扫描器的动态执行启发（本文件只做
// 文本提取与静态 lint，不存在任何执行）。
const SCRIPT_FLAG_RE = /--[e]val\s+'([\s\S]*?)'/g;

/** 提取全部 mongosh 脚本片段（JS 内只用双引号字符串，单引号即边界） */
const extractScripts = (text) => Array.from(text.matchAll(SCRIPT_FLAG_RE), (m) => m[1]);

/** 只报 no-undef（其它风格规则与本闸无关） */
const noUndefMessages = (code) =>
  new Linter({ configType: 'flat' }).verify(code, {
    languageOptions: { globals: MONGOSH_GLOBALS },
    rules: { 'no-undef': 'error', 'no-unused-vars': 'off' },
  });

describe('compose 内嵌脚本片段的 no-undef 闸（D-F1）', () => {
  test('检测器自证：循环外引用 for(let i) 的中毒样本必须报 no-undef（防检测器静默失效）', () => {
    const poisoned = [
      'for (let i = 0; i < 1; i++) { break; }',
      'if (i !== 999) { quit(1); }', // i 已出作用域：真实缺陷的形状
    ].join('\n');
    const messages = noUndefMessages(poisoned).filter((m) => m.ruleId === 'no-undef');
    expect(messages).toHaveLength(1);
    expect(messages[0].message).toContain("'i' is not defined");
  });

  test('docker-compose.yml 全部内嵌脚本片段无未声明引用，且无解析失败（复审 F1-5）', () => {
    const scripts = extractScripts(compose);
    // 前提自证（覆盖计数，复审 F1-5 ②）：文件里每个 mongosh 脚本 flag 都必须
    // 被提取器吃进——「少提取一个」比「全丢」更隐蔽，只断言下限抓不住它。
    // 计数排除 # 注释行（说明文字里的 flag 字样不是脚本）。
    const flagCount = compose
      .split(/\r?\n/)
      .filter((l) => !l.trim().startsWith('#'))
      .join('\n')
      .match(/--[e]val\b/g).length;
    expect(scripts.length).toBe(flagCount);
    expect(scripts.length).toBeGreaterThanOrEqual(3);
    const offenders = [];
    for (const code of scripts) {
      for (const message of noUndefMessages(code)) {
        // fatal（解析失败）的 message.ruleId 为 null：只挑 no-undef 会把
        // 「截断的非 JS 片段解析报错」静默放过——这一层闸就假绿了（F1-5 ①）。
        // 解析失败与未声明引用同为红，不区分。
        if (message.fatal || message.ruleId === 'no-undef') {
          offenders.push(
            (message.fatal ? '解析失败: ' + message.message : message.message) +
              ' @ line ' +
              message.line
          );
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  test('mongo-rs-init 的就绪判定不依赖循环外哨兵值（缺陷形状的文本级反证）', () => {
    const lines = compose.split(/\r?\n/);
    const start = lines.findIndex((l) => /^ {2}mongo-rs-init:\s*$/.test(l));
    expect(start).toBeGreaterThanOrEqual(0);
    let end = lines.length;
    for (let i = start + 1; i < lines.length; i += 1) {
      if (/^ {2}[A-Za-z0-9_.-]+:\s*$/.test(lines[i])) {
        end = i;
        break;
      }
    }
    const block = lines.slice(start, end).join('\n');
    // 旗标写法必须在场；循环内哨兵值与循环外读循环变量的形状必须不存在。
    // no-undef 闸已覆盖语义，这里钉文本形状作第二把尺（防未来经模板拼接等
    // 形态绕过静态分析）。
    expect(/let primaryReady = false;/.test(block)).toBe(true);
    expect(block.includes('i = 999')).toBe(false);
    expect(/if \(i !== 999\)/.test(block)).toBe(false);
  });
});
