'use strict';

/**
 * （2026-09-19）：错误码的第三条腿——「调用点发出的码必须已注册」
 *
 * 注册表既有的两道契约（`errorCodes.test.js:273/279`）双向对齐了
 * `ERROR_CODES` ↔ 前端 i18n 映射表，validateRegistry 又逐条校验了 status/message。
 * 但**没有任何门禁检查调用点**：`ApiResponse.codeError(res, 'ALARM_NOTFOUND')`
 * 这种拼错的码可以一路过全部门禁进生产——运行时只在日志里留一行 error，
 * 而客户端拿到的是未注册码 + 兜底 400 + 通用文案「操作失败」，
 * 前端映射表里没有这个码 ⇒ 用户看到未翻译文案，且 HTTP 语义从 404 变成 400。
 * 注册表自称"后端唯一事实来源"，事实来源必须与产出点对账。
 *
 * 实测（扫描 src/ 136 个非测试文件、190 个字面量码）：当前**零未注册码**，
 * 所以本文件是防漂移的门禁而非缺陷修复；同时把"注册了却没人发"的死码封成封闭清单。
 */

const fs = require('fs');
const path = require('path');
const { ERROR_CODES, validateRegistry } = require('../../src/utils/errorCodes');

const SRC = path.join(__dirname, '../../src');

/**
 * 从一段源码里抽出"会以 errorCode 形式发给客户端"的码字面量。
 * 三条通道：codeError(res, 'CODE')、errors:{errorCode:'CODE'}、
 * 以及结构化违规对象的 code 字段（如 utils/superAdmin.js 的
 * {code:'SUPER_ADMIN_ROLE_NOT_DETACHABLE', message:'…'}，由控制器转交 codeError）。
 *
 * 第三条必须同时要求下一行是 message: ——只按 `code: '大写蛇形',` 匹配会一路撞上
 * services/initData.js 里的**角色** code（'SUPER_ADMIN' / 'GUEST' …），
 * 那是业务标识不是错误码（实测把 5 个角色码误报成未注册错误码）。
 * 变量传参（如 codeError(res, violation.code)）静态不可见，由 codeError 的
 * 运行期兜底日志负责——这也是把 {code, message} 形态纳入扫描的原因。
 * 第四通道同理：controllers/roleGuards.js 的 guardRoleWithinOperatorLevel 收
 * forbiddenCode/higherLevelCode 两个参数由 codeError(res, 参数) 发出，码字面量在
 * roleController 的调用点上。两个属性名在该仓专属，不会误伤别处对象字段。
 * 第五通道：#12 之后"范围不可用"由 middleware/rbac.js 的 deniedDataScope 以
 * `new ApiError(msg, status, errors, 'DATA_SCOPE_DENIED')` 抛出，errorHandler 再把
 * 它转成 errors.errorCode 发给客户端——这同样是一条"码抵达客户端"的通路。少了它，
 * DATA_SCOPE_DENIED 会被判成死码（注册了却没人发）。
 */
const CODE_PATTERNS = [
  /codeError\(\s*[A-Za-z_$][\w.]*\s*,\s*'([A-Z][A-Z0-9_]*)'/g,
  /\berrorCode:\s*'([A-Z][A-Z0-9_]*)'/g,
  /^\s*code:\s*'([A-Z][A-Z0-9_]{3,})',\s*\r?\n\s*message:/gm,
  /\b(?:forbiddenCode|higherLevelCode):\s*'([A-Z][A-Z0-9_]*)'/g,
  // 末位实参是码字面量的 new ApiError(...)。[^)]* 不跨右括号，正好框住实参表；
  // 今天全仓只有一处命中（rbac.deniedDataScope），多一处就会在这里现形。
  /new ApiError\([^)]*["']([A-Z][A-Z0-9_]*)["']\s*\)/gs,
];

function collectCodesFromSource(text) {
  const found = new Set();
  for (const re of CODE_PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) found.add(m[1]);
  }
  return found;
}

/** 递归取 src/ 下的生产源码文件（排除测试目录） */
function listProductionFiles(dir = SRC, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.name === 'tests' || entry.name === 'node_modules') continue;
    if (entry.isDirectory()) listProductionFiles(full, out);
    else if (entry.name.endsWith('.js') && !entry.name.endsWith('.test.js')) out.push(full);
  }
  return out;
}

const files = listProductionFiles();
const emitted = new Map(); // code -> [file,...]
for (const f of files) {
  for (const code of collectCodesFromSource(fs.readFileSync(f, 'utf8'))) {
    if (!emitted.has(code)) emitted.set(code, []);
    emitted.get(code).push(path.relative(SRC, f));
  }
}

describe('调用点错误码必须已注册', () => {
  test('扫描确实覆盖到规模（防止路径/正则空转把下面的断言变成恒真）', () => {
    expect(files.length).toBeGreaterThan(100);
    expect(emitted.size).toBeGreaterThan(150);
    // 前提自证：已知在用的码必须被抽到，否则是提取器坏了而不是代码干净
    for (const known of ['AUTH_INVALID_CREDENTIALS', 'MFA_CODE_INVALID', 'FULL_RANGE_FORBIDDEN']) {
      expect(emitted.has(known)).toBe(true);
    }
    // 反向前提：角色标识不得被扫进来（第一版正则就是这样误报 5 个角色码的）。
    // 有人放宽第三条通道时，这条会先红，而不是把"未注册错误码"的判据污染成噪音。
    for (const roleCode of ['SUPER_ADMIN', 'SECURITY_ADMIN', 'GUEST', 'FIREFIGHTER']) {
      expect(emitted.has(roleCode)).toBe(false);
    }
    // 注册表自检函数本身仍然零问题（这条与既有套件重叠一次，成本为零）
    expect(validateRegistry()).toEqual([]);
  });

  test('每个以字面量发出的码都在注册表里（拼错的码今天就会被 CI 拦下）', () => {
    const unregistered = [...emitted.keys()]
      .filter((code) => !ERROR_CODES[code])
      .map((code) => `${code} ← ${[...new Set(emitted.get(code))].join(', ')}`);
    expect(unregistered).toEqual([]);
  });

  test('提取器 + 判据有牙齿：合成一段带拼错码的源码，必须被报出来', () => {
    const synthetic = [
      "  return ApiResponse.codeError(res, 'ALARM_NOTFOUND_TYPEO');",
      "  return ApiResponse.error(res, 'x', 400, { errorCode: 'CAPTCHA_INVALLID' });",
      "  throw new ApiError(ERROR_CODES.X.message, 403, undefined, 'DATA_SCOPE_DENIEDX');",
      '  const violation = {',
      "    code: 'SUPER_ADMIN_ROLE_NOT_DETACHABLX',",
      "    message: 'x',",
      '  };',
    ].join('\n');
    const codes = [...collectCodesFromSource(synthetic)];
    expect(codes).toEqual([
      'ALARM_NOTFOUND_TYPEO',
      'CAPTCHA_INVALLID',
      'SUPER_ADMIN_ROLE_NOT_DETACHABLX',
      'DATA_SCOPE_DENIEDX',
    ]);
    const bad = codes.filter((c) => !ERROR_CODES[c]);
    expect(bad).toHaveLength(4);
    // 对照：真码走同一条路径必须被放过（证明上面报的是"未注册"而不是"有内容"）
    expect([...collectCodesFromSource(synthetic)].filter((c) => ERROR_CODES[c]).length).toBe(0);
    expect([...collectCodesFromSource("ApiResponse.codeError(res, 'MFA_CODE_INVALID');")]).toEqual([
      'MFA_CODE_INVALID',
    ]);
  });

  test('注册了却无人发送的死码是封闭清单（新增死码必须在此登记理由）', () => {
    // 已知两条：全网段收口最终统一走 FULL_RANGE_FORBIDDEN + 动态 message，
    // 这两个更细的码随之失去调用方。前端映射表仍有对应条目（跨车道改动，未清理），
    // 因此保留注册表条目以维持「后端码 ↔ 前端映射」双向等式，但把"死码"这件事写死在这里：
    // 谁再往注册表加不发出去的码，这条断言会红，逼他说明理由。
    const dead = Object.keys(ERROR_CODES).filter((code) => !emitted.has(code));
    expect(dead.sort()).toEqual([
      'IP_FULL_RANGE_REMOVE_SUPER_ADMIN_ONLY',
      'IP_FULL_RANGE_SUPER_ADMIN_ONLY',
    ]);
  });
});
