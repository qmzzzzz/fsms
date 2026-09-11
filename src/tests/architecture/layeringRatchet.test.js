/**
 * 分层纪律棘轮（D-1a）
 *
 * 现状：controller 仍有 28 处直接 require models（绕过 service 层）。
 * 下沉是渐进工作，但「边下沉边新增」会让收敛永远到不了——因此用棘轮锁住：
 *
 *  1. 已登记的直连文件，数量只许减不许增（减到 0 后从名单移除）；
 *  2. 未登记的新 controller 一律禁止直连 models（0 容忍），
 *     新功能必须经 services/ 层；
 *  3. 总直连数不得超过当前基线。
 *
 * 完成下沉的正确姿势：把数据访问移入对应 service，更新（调低）本文件基线，
 * 全量测试通过后提交。
 */

const fs = require('fs');
const path = require('path');

const CONTROLLERS_DIR = path.join(__dirname, '../../controllers');

// 2026-08-30 实测基线（每文件直连 require('../models/*') 次数）
const GRANDFATHERED = {
  'ipListController.js': 6,
  'securityController.js': 6,
  'reportController.js': 4,
  'roleController.js': 0,
  'authController.js': 2,
  'mfaController.js': 2,
  'permissionController.js': 0,
  'userController.js': 0,
  'auditController.js': 1,
};

const TOTAL_BASELINE = Object.values(GRANDFATHERED).reduce((a, b) => a + b, 0); // 28

const countDirectModelRequires = (source) =>
  (source.match(/require\('\.\.\/models\//g) || []).length;

describe('分层纪律棘轮（D-1a）', () => {
  const files = fs
    .readdirSync(CONTROLLERS_DIR)
    .filter((f) => f.endsWith('.js') && !f.endsWith('.test.js'));

  test('已登记文件的直连数只许减不许增', () => {
    for (const [file, allowed] of Object.entries(GRANDFATHERED)) {
      const full = path.join(CONTROLLERS_DIR, file);
      if (!fs.existsSync(full)) continue; // 文件整体移除是好事
      const count = countDirectModelRequires(fs.readFileSync(full, 'utf8'));
      expect(count).toBeLessThanOrEqual(allowed);
    }
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
