/**
 * 分层纪律棘轮（D-1a）
 *
 * 现状：controller 仍有 28 处直接 require models（绕过 service 层）。
 * 下沉是渐进工作，但「边下沉边新增」会让收敛永远到不了——因此用棘轮锁住：
 *
 *  1. 已登记的直连文件，实测数必须**等于**基线：多了是新增直连（拦），
 *     少了是基线没跟着调低（同样拦）——只许 `<=` 的话，一次"下沉但忘了改基线"
 *     就会把白嫖额度重新留下，那正是本文件头记过的事故；减到 0 后从名单移除；
 *  2. 未登记的新 controller 一律禁止直连 models（0 容忍），
 *     新功能必须经 services/ 层；
 *  3. 总直连数不得超过当前基线（1+2 成立时它必然成立，留作聚合视角的失败信息）。
 *
 * 完成下沉的正确姿势：把数据访问移入对应 service，更新（调低）本文件基线，
 * 全量测试通过后提交。
 */

const fs = require('fs');
const path = require('path');

const CONTROLLERS_DIR = path.join(__dirname, '../../controllers');

// 直连基线（本次改动复审重新标定：2026-09-17 实测，计数口径见下方 countDirectModelRequires）
// 上一版的两处问题：
//   ① 注释写「28」，而对象实际求和为 21——注释与代码不一致（本次改动报告反复强调的那类缺陷）；
//   ② reportController(4→1) 与 securityController(6→5) 声明值高于实测，棘轮因此留出
//      4 次「白嫖额度」：新增 4 处直连也不会变红，等于门禁形同虚设。
// 现按实测值申报，任何一处新增直连都会立即触发失败。
const GRANDFATHERED = {
  'ipListController.js': 6,
  'securityController.js': 5,
  'reportController.js': 1,
  'roleController.js': 0,
  'authController.js': 2,
  'mfaController.js': 2,
  'permissionController.js': 0,
  'userController.js': 0,
  'auditController.js': 1,
};

const TOTAL_BASELINE = Object.values(GRANDFATHERED).reduce((a, b) => a + b, 0); // 17（与实测一致）

// 计数口径（本次改动复审修正）：原正则只认 require('../models/Xxx') 单引号带斜杠形态，
// 实测漏掉 authController.js:96 的 require('../models')（无斜杠，走 index 聚合入口）——
// 该形态同样绕过 service 层；原基线声明 authController=2 而旧正则实测仅 1，差值正是它。
// 现覆盖 4 种等价形态：单引号、双引号、无斜杠聚合入口、反引号。
const countDirectModelRequires = (source) =>
  (source.match(/require\(\s*['"`]\.\.\/models(?:\/[^'"`]*)?['"`]\s*\)/g) || []).length;

describe('分层纪律棘轮（D-1a）', () => {
  const files = fs
    .readdirSync(CONTROLLERS_DIR)
    .filter((f) => f.endsWith('.js') && !f.endsWith('.test.js'));

  test('已登记文件的直连数必须**等于**基线（既不许增，也不许留着没调低的额度）', () => {
    // 判据从 `<=` 改成 `==` 的理由就是本文件头记着的那次事故：reportController(4→1)
    // 与 securityController(6→5) 的声明值高于实测，棘轮因此白留 4 次额度——新增直连不红，
    // 门禁形同虚设。而 `<=` 本身**防不住下一次**：有人下沉 2 处直连却忘了调低基线，
    // 白嫖额度立刻回来，且这正好是注释里承诺的"更新基线"流程未被强制。
    // 所以：下沉之后必须把 GRANDFATHERED 一起改小（本仓的既有口径，不是新约定）。
    for (const [file, allowed] of Object.entries(GRANDFATHERED)) {
      const full = path.join(CONTROLLERS_DIR, file);
      if (!fs.existsSync(full)) continue; // 文件整体移除是好事
      const count = countDirectModelRequires(fs.readFileSync(full, 'utf8'));
      expect({ file, measured: count, declared: allowed }).toEqual({
        file,
        measured: allowed,
        declared: allowed,
      });
    }
  });

  test('计数口径自证：注释承诺的 4 种等价形态真的各算一次', () => {
    // 头注释第 44 行宣称"现覆盖 4 种等价形态"，此前本文件**没有一条用例**验证它——
    // 那就是"注释即事实"的破口（口径改回单引号也不会红）。
    const forms = {
      单引号: "const M = require('../models/FireAlarm');",
      双引号: 'const M = require("../models/FireAlarm");',
      反引号: 'const M = require(`../models/FireAlarm`);',
      无斜杠聚合入口: "const M = require('../models');",
    };
    for (const [name, src] of Object.entries(forms)) {
      expect({ form: name, n: countDirectModelRequires(src) }).toEqual({ form: name, n: 1 });
    }
    // 反向对照：不属于"绕过 service 层"的形态不得计数，否则基线是虚高的
    for (const src of [
      "const M = require('../../models');", // 不是 controllers 的相对路径写法
      "const s = require('../services/AlarmService');",
      'const M = require("./models");',
    ]) {
      expect(countDirectModelRequires(src)).toBe(0);
    }
    // 前提自证：真实文件里确实存在"无斜杠聚合入口"这一形态（注释第 41-43 行的事实）
    const authSrc = fs.readFileSync(path.join(CONTROLLERS_DIR, 'authController.js'), 'utf8');
    expect(authSrc).toMatch(/require\(\s*'\.\.\/models'\s*\)/);
    expect(countDirectModelRequires(authSrc)).toBe(GRANDFATHERED['authController.js']);
  });

  test('未登记的新 controller 禁止直连 models（必须经 service 层）', () => {
    for (const file of files) {
      if (GRANDFATHERED[file]) continue;
      const count = countDirectModelRequires(
        fs.readFileSync(path.join(CONTROLLERS_DIR, file), 'utf8')
      );
      expect({ file, count }).toEqual({ file, count: 0 });
    }
  });

  test('全量直连总数不超过基线', () => {
    const total = files.reduce(
      (sum, file) =>
        sum + countDirectModelRequires(fs.readFileSync(path.join(CONTROLLERS_DIR, file), 'utf8')),
      0
    );
    expect(total).toBeLessThanOrEqual(TOTAL_BASELINE);
  });
});
