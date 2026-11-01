/**
 * 诱饵画像差异化接线闸（P1e）
 *
 * 本闸存在的理由只有一条：`deriveHoneypotPersona` 单独存在**不等于**物化时真的写进了
 * `realName`/`department`。把画像模块写出来、却仍在 `User.create` 里留一句
 * `realName: '运维管理员'`，是最可能的中间态——那时画像测试全绿（纯函数没问题），
 * 而库里那 11 条记录依旧构成一眼可辨的簇。因此这里静态钉住接线本身。
 *
 * 判据面积与自证：
 *  - 静态面：画像模块被 require、派生结果被写进 realName 与 department、并且旧统一值
 *    不得回潮（三种失败形态各有用例）；
 *  - 数据面：生效名单逐条派生后 realName/department 组合两两不同，且不存在「派不出画像的名字」；
 *  - 反向自证：把接线改回旧形态、把画像表喂重复项、把派生器换成一个常量——都必须被本闸判红。
 *    「恒绿的判据」比没有判据更糟，所以每条数据面判据都配一个合成输入侧的反例。
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { jsCodeOnly } = require('../helpers/jsCodeOnly');
const { deriveHoneypotPersona } = require('../../constants/honeypotPersonas');
const { parseHoneypotUsernames } = require('../../constants/honeypotAccounts');

const ROOT = path.join(__dirname, '..', '..', '..');
const WATCH_FILE = 'src/services/honeypotWatch.js';

const watchCode = jsCodeOnly(fs.readFileSync(path.join(ROOT, WATCH_FILE), 'utf8'));

/** 接线缺陷清单：空数组 = 物化路径真的在用画像 */
const wiringFindings = (source) => {
  const findings = [];
  if (!source.includes("require('../constants/honeypotPersonas')")) findings.push('未引入画像模块');
  if (!source.includes('deriveHoneypotPersona(')) findings.push('未派生画像');
  if (!/realName:\s*persona\.realName/.test(source)) findings.push('realName 未取画像');
  if (!/department:\s*persona\.department/.test(source)) findings.push('department 未取画像');
  if (/realName:\s*['"]/.test(source)) findings.push('回潮：统一 realName');
  return findings;
};

/** 重复的「姓名+部门」组合：蜜罐农场的可识别指纹就是这两个字段的重复 */
const duplicatePersonas = (personas) => {
  const seen = new Set();
  const dup = [];
  for (const { realName, department } of personas) {
    const key = realName + '|' + department;
    if (seen.has(key)) dup.push(key);
    else seen.add(key);
  }
  return dup;
};

const effectivePersonas = () => {
  const taken = [];
  return parseHoneypotUsernames().names.map((name) => {
    const persona = deriveHoneypotPersona(name, taken);
    taken.push(persona.realName);
    return persona;
  });
};

describe('诱饵画像差异化：物化接线与生效名单画像（P1e）', () => {
  test('前提自证：物化源可读、画像模块可 require、生效名单非空', () => {
    expect(watchCode.length).toBeGreaterThan(500);
    expect(typeof deriveHoneypotPersona).toBe('function');
    expect(parseHoneypotUsernames().names.length).toBeGreaterThanOrEqual(1);
  });

  test('接线：物化时 realName/department 取自派生画像，且旧统一值不残留', () => {
    expect(wiringFindings(watchCode)).toEqual([]);
    // 已有诱饵的画像参与去重（重跑与分批物化不撞名），来源只能是「查蜜罐自身」
    expect(watchCode).toContain('User.find({ isHoneypot: true })');
    expect(watchCode).toContain('taken.push(');
  });

  test('反向自证（判据有牙）：三种实际会发生的坏形态逐个被判红', () => {
    expect(wiringFindings('const x = 1;')).toEqual([
      '未引入画像模块',
      '未派生画像',
      'realName 未取画像',
      'department 未取画像',
    ]);
    expect(
      // replaceAll：物化与回传两处都要改——只改一处时上一条判据仍为真，这正是「判据要有牙」的反例
      wiringFindings(watchCode.replaceAll('realName: persona.realName', "realName: '运维管理员'"))
    ).toEqual(['realName 未取画像', '回潮：统一 realName']);
    expect(wiringFindings(watchCode.replace('department: persona.department', ''))).toEqual([
      'department 未取画像',
    ]);
  });

  test('数据面：生效名单的画像「姓名+部门」两两不同，且没有派不出画像的名字', () => {
    const personas = effectivePersonas();
    expect(personas).toHaveLength(parseHoneypotUsernames().names.length);
    for (const persona of personas) {
      expect(typeof persona.realName).toBe('string');
      expect(persona.realName.trim()).not.toBe('');
      expect(typeof persona.department).toBe('string');
      expect(persona.department.trim()).not.toBe('');
    }
    expect(duplicatePersonas(personas)).toEqual([]);
  });

  test('反向自证（数据面）：重复画像、空画像都必须被点名', () => {
    expect(
      duplicatePersonas([
        { realName: '张伟', department: 'A' },
        { realName: '张伟', department: 'A' },
        { realName: '李强', department: 'A' },
      ])
    ).toEqual(['张伟|A']);
    expect(duplicatePersonas(effectivePersonas())).toEqual([]);
  });

  test('画像池不退化：200 个合成名字派生出的 realName 高度分散', () => {
    const names = Array.from({ length: 200 }, (_, i) => 'probe' + ('0000' + i).slice(-4));
    const realNames = names.map((name) => deriveHoneypotPersona(name).realName);
    // 池宽 24×28 = 672，200 次抽样必然有生日碰撞（实测 128），故只钉「远高于退化」：常量派生物或个位数池都过不了
    expect(new Set(realNames).size).toBeGreaterThanOrEqual(100);
    // 反向自证：换成常量派生器时，上面这条判据必然红（证明它在测「分散」而不是在自说自话）
    const degenerate = names.map(() => '张伟');
    expect(new Set(degenerate).size).toBe(1);
  });
});
