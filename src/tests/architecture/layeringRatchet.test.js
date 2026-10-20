/**
 * 分层纪律棘轮（D-1a）
 *
 * 现状：controller 仍有 8 处直接 require models（绕过 service 层）。
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
const MODELS_DIR = path.join(__dirname, '../../models');

// 直连基线（本次改动复审重新标定：2026-09-17 实测，计数口径见下方 countDirectModelRequires）
// 上一版的两处问题：
//   ① 注释写「28」，而对象实际求和为 21——注释与代码不一致（本次改动报告反复强调的那类缺陷）；
//   ② reportController(4→1) 与 securityController(6→5) 声明值高于实测，棘轮因此留出
//      4 次「白嫖额度」：新增 4 处直连也不会变红，等于门禁形同虚设。
// 现按实测值申报，任何一处新增直连都会立即触发失败。
// 2026-10-19 拆分 authController.js 后：原 'authController.js': 2 的两处直连随迁至
// authController/credentials.js（require('../../models')，无斜杠聚合入口）与
// authController/profile.js（require('../../models/AuditLog')）；键名是**相对
// controllers/ 的路径**（含子目录），总数不变。
// 2026-10-19 批 3c-2 拆分 userController.js 后：其 0 值键随文件移除退场，
// 新目录各文件实测 0 直连，按"未登记新 controller 一律 0 容忍"判据覆盖，无需登记。
// 2026-10-19 批 3c-3 拆分 securityController.js 后：原 5 处直连中 3 处（User/AuditLog/
// SystemConfig）集中进 shared.js；另 2 处函数内惰性直连随迁 admin.js（Role）与
// overview.js（AuditLog），搬家后相对深度已同步加深一层。键名是相对 controllers/ 的
// 路径（含子目录），总数不变。
// 2026-10-20 A-4 读路径下沉：ipListController 的 6 处（名单读写 + 操作者超管判定）
// 整体迁入 services/ipListService.js；reportController 的报警聚合迁入
// reportStatsService.getAlarmReportData；admin.js 的角色查询改用 roleService.findRolesByIds；
// overview.js 删除对 AuditLog 的重复 require（改用 shared 已提供的同一模型入口）。
// 四处实测归零，按"减到 0 后从名单移除"退场，剩余 8 处继续由棘轮锁定。
const GRANDFATHERED = {
  'securityController/shared.js': 3,
  'authController/credentials.js': 1,
  'authController/profile.js': 1,
  'mfaController.js': 2,
  'auditController.js': 1,
};

const TOTAL_BASELINE = Object.values(GRANDFATHERED).reduce((a, b) => a + b, 0); // 8（与实测一致）

// 计数口径（2026-10-19 改成**路径解析**，历史两版一并记下）：
//   · 初版正则只认 require('../models/Xxx') 单引号带斜杠形态，实测漏掉无斜杠聚合入口
//     require('../models')（拆分前 authController.js:131，同样绕过 service 层）；
//     原基线声明 authController=2 而旧正则实测仅 1，差值正是它。
//   · 二版把正则扩到 4 种字面形态（单引号/双引号/反引号/无斜杠）。本轮把它用于
//     controllers/authController/ 子目录时暴露了根问题：**深度是文本猜出来的**——
//     '../models' 与 '../../models' 得按文件所在位置各写一种，文件一搬家口径就得跟着改。
//   · 现取每个相对 require 的 specifier，按文件所在目录 path.resolve 后判断是否落在
//     src/models/ 之内（按 MODELS_DIR + path.sep 的目录边界比较，同前缀目录不误收）。
//     引号形态、括号内空白、任意嵌套深度全部归一；"嵌套文件里误写 '../models'（会解析到
//     controllers/models）"这类真实错误形态会被正确地**不**计数（覆盖见自证用例）。
// 口径扫**原文**、不剥注释（沿用全仓扫描器惯例），所以注释里别写代码形状的字面量——
// 本文件头记过的那次假红就是这么来的；而注释里的 `…`/省略号形态不以 '.' 开头，
// 不是相对路径，天然不计。
const countDirectModelRequires = (source, fileAbs) => {
  const dir = path.dirname(fileAbs);
  let count = 0;
  const re = /require\(\s*(['"`])([^'"`]+)\1\s*\)/g;
  let m;
  while ((m = re.exec(source)) !== null) {
    if (!m[2].startsWith('.')) continue;
    const resolved = path.resolve(dir, m[2]);
    if (resolved === MODELS_DIR || resolved.startsWith(MODELS_DIR + path.sep)) count += 1;
  }
  return count;
};

/** controllers/ 下全部非测试 .js 的相对路径（'/' 分隔，含子目录——键名与基线同一坐标系） */
function controllerFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.js') && !entry.name.endsWith('.test.js')) {
        out.push(path.relative(CONTROLLERS_DIR, full).replace(/\\/g, '/'));
      }
    }
  };
  walk(CONTROLLERS_DIR);
  return out;
}

describe('分层纪律棘轮（D-1a）', () => {
  test('已登记文件的直连数必须**等于**基线（既不许增，也不许留着没调低的额度）', () => {
    // 判据从 `<=` 改成 `==` 的理由就是本文件头记着的那次事故：reportController(4→1)
    // 与 securityController(6→5) 的声明值高于实测，棘轮因此白留 4 次额度——新增直连不红，
    // 门禁形同虚设。而 `<=` 本身**防不住下一次**：有人下沉 2 处直连却忘了调低基线，
    // 白嫖额度立刻回来，且这正好是注释里承诺的"更新基线"流程未被强制。
    // 所以：下沉之后必须把 GRANDFATHERED 一起改小（本仓的既有口径，不是新约定）。
    for (const [file, allowed] of Object.entries(GRANDFATHERED)) {
      const full = path.join(CONTROLLERS_DIR, file);
      if (!fs.existsSync(full)) continue; // 文件整体移除是好事
      const count = countDirectModelRequires(fs.readFileSync(full, 'utf8'), full);
      expect({ file, measured: count, declared: allowed }).toEqual({
        file,
        measured: allowed,
        declared: allowed,
      });
    }
  });

  test('计数口径自证：路径解析真的按文件位置归一（5 种形态各算一次，5 种反例都不算）', () => {
    // 头注释宣称口径覆盖"引号形态、括号内空白、任意嵌套深度"——本文件此前没有一条用例
    // 逐一验证它（"注释即事实"的破口）。样本的"文件位置"用真控制器坐标系合成：
    const topFile = path.join(CONTROLLERS_DIR, 'syntheticController.js');
    const nestedFile = path.join(CONTROLLERS_DIR, 'authController/synthetic.js');
    const forms = {
      单引号: "const M = require('../models/FireAlarm');",
      双引号: 'const M = require("../models/FireAlarm");',
      反引号: 'const M = require(`../models/FireAlarm`);',
      无斜杠聚合入口: "const M = require('../models');",
      嵌套目录里的深一层写法: "const M = require('../../models');",
    };
    for (const [name, src] of Object.entries(forms)) {
      const file = name === '嵌套目录里的深一层写法' ? nestedFile : topFile;
      expect({ form: name, n: countDirectModelRequires(src, file) }).toEqual({ form: name, n: 1 });
    }
    // 反向对照：不属于"绕过 service 层"的形态不得计数，否则基线是虚高的。
    // "嵌套写浅一层 / 顶层写深一层"是本轮补的关键两条：深度必须由文件位置算出，
    // 而不是把两种字面量都收进来（那会让搬家后的文件漏网或被误报）。
    const counterExamples = [
      ['嵌套文件误写浅一层', "const M = require('../models');", nestedFile],
      ['顶层文件误写深一层', "const M = require('../../models');", topFile],
      ['服务层不受影响', "const s = require('../services/AlarmService');", topFile],
      ['同目录 ./models 不是 src/models', 'const M = require("./models");', topFile],
      ['裸模块名不是相对路径', "const M = require('models');", topFile],
    ];
    for (const [name, src, file] of counterExamples) {
      expect({ form: name, n: countDirectModelRequires(src, file) }).toEqual({ form: name, n: 0 });
    }
    // 前提自证：拆分后的真实文件里确实存在"无斜杠聚合入口"这一形态（嵌套坐标系下写作 ../../models）
    const credPath = path.join(CONTROLLERS_DIR, 'authController/credentials.js');
    const credSrc = fs.readFileSync(credPath, 'utf8');
    expect(credSrc).toMatch(/require\(\s*'\.\.\/\.\.\/models'\s*\)/);
    expect(countDirectModelRequires(credSrc, credPath)).toBe(
      GRANDFATHERED['authController/credentials.js']
    );
    // 走查自证：递归收集真的走到了嵌套目录（否则上面的样本与真实文件是两个坐标系）
    expect(controllerFiles()).toContain('authController/credentials.js');
  });

  test('未登记的新 controller 禁止直连 models（必须经 service 层）', () => {
    for (const file of controllerFiles()) {
      if (Object.prototype.hasOwnProperty.call(GRANDFATHERED, file)) continue;
      const full = path.join(CONTROLLERS_DIR, file);
      const count = countDirectModelRequires(fs.readFileSync(full, 'utf8'), full);
      expect({ file, count }).toEqual({ file, count: 0 });
    }
  });

  test('全量直连总数不超过基线', () => {
    const total = controllerFiles().reduce((sum, file) => {
      const full = path.join(CONTROLLERS_DIR, file);
      return sum + countDirectModelRequires(fs.readFileSync(full, 'utf8'), full);
    }, 0);
    expect(total).toBeLessThanOrEqual(TOTAL_BASELINE);
  });
});
