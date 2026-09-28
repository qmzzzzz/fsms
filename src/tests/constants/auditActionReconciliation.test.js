/**
 * 审计 action 自动对账（P1-11 / P3-61）
 *
 * 缺陷（P1-11）：\`authService.js\` 写入 action=\`account_temp_locked\` 的审计记录，
 * 但 \`constants/audit.js\` 的 AUDIT_LOG_ACTIONS 白名单缺此条 —— 记录在库里，
 * 而 \`utils/auditQuery.js\` 的 validateEnum(action, AUDIT_LOG_ACTIONS) 会让
 * **按该 action 筛选的查询直接 400**（"审计留痕形同虚设"：写了却查不出来）。
 * 同类漂移在 P3-11 已发生过一次（路由派生 action 滞后），本次以自动对账防复发。
 *
 * 本测试**不手写 action 列表**（手写等于把"对账"退化成"复制"）：它扫描 src/
 * 下所有审计写入调用点，从源码里**解析出实际写入的 action 字符串**，
 * 再断言该集合 ⊆ AUDIT_LOG_ACTIONS。
 *
 * ===== 扫描口径（重要，改动前请先读）=====
 *
 * 1. 识别五类写入调用（与 models/auditLogWriteStatics.js 的静态方法一一对应）：
 *      - AuditLog.record({ ... })          事件型/安全告警
 *      - AuditLog.create({ ... })          直写（控制器/服务）
 *      - AuditLog.recordSensitiveAction(uid, uname, ACTION, category, ...)  第 3 参
 *      - auditBuffer.push({ ... })         全局中间件批量写
 *      - this.create({ ... })              **静态方法自身决定 action**（F-201 补）
 *    匹配用「括号配平」而不是正则行匹配：调用实参跨多行、字符串内含 ')' 都不影响。
 *    前五类都以 `AuditLog.` / `auditBuffer.` 为前缀，于是 recordLogin 里的
 *    `this.create({ action: success ? 'login_success' : 'login_failed' })` 整个不在
 *    对账范围内。实测（2026-09-26）：把它改成未登记的 `'login_denied'`，本文件与可达性
 *    用例（9 例）外加 7 个引用 login_failed 的套件（107 例）**全绿**，而运行期后果是
 *    recordLogin 每次失败登录都撞 mongoose enum ValidationError —— 审计直接断档。
 *
 *    第五类带来的新问题：静态方法体内也有**转发型**写法（`this.create(entry)`、
 *    `{ action, ... }` 简写），其 action 由调用方决定、本处没有字面量可解析。这类
 *    按「转发」记账而不是静默跳过（见 FORWARDexpected），新增转发点必须显式改判——
 *    否则"跳过"本身就成了下一个盲区。
 *
 * 2. action 取值表达式只解析以下四种形态（其余一律**报错**而不是静默跳过，
 *    避免新写法悄悄逃出对账范围）：
 *      - 字符串字面量：              action: 'mfa_disable'
 *      - 三元两个字面量：            action: locked ? 'user_locked' : 'user_unlocked'
 *      - ALERT_TYPES 常量：          action: ALERT_TYPES.BRUTE_FORCE
 *                                    （常量表从 securityAlert.js 实际导出读取，不复制字面量）
 *      - meta.action（早于 auditLog 中间件的 403 转发）：
 *                                    middleware/security.js 的 recordEarlyRejection（2026-09-17 时为 :359），
 *                                    是唯一写入方，其 action 由调用方传入。此处扫描
 *                                    全仓 recordEarlyRejection( 调用点取出字面量 action。
 *
 * 3. 排除项及原因：
 *      - 查询/过滤上下文（如 securityController 最近登录记录查询里的 action: { $in: [...] }）：
 *        不是写入调用，自然不在四类调用的实参扫描范围内。
 *      - 子文档 action（FireAlarm/Inspection 的 processLog、AlarmService 的
 *        executionLog、roleController/userController/rolePermissionController 的
 *        WebSocket payload）：不是 AuditLog 写入，同上不匹配。
 *        ⚠ F-203：本条理由**原先只是描述**——"不匹配"意味着主扫描器对新增的写入形态
 *        同样静默失明。现在它是一笔可核对的账：`NOT_AUDIT_ACTION_LITERALS` 逐条列出
 *        (文件, action, 家族, 行号)，由「回球闸」用例双向钉住（漏登记 ⇒ 红，条目烂掉 ⇒ 红）。
 *      - middleware/security.js 的 auditBuffer.push（2026-09-17 时为 :689）用 deriveAuditMeta(req)
 *        派生 action（路由派生型），其覆盖面由 src/tests/utils/auditMeta.test.js
 *        的「路由派生 action ⊆ 白名单」用例负责，本文件不重复断言。
 *      - 动态拼接/变量型 action：本扫描会解析失败并**抛出**（见上条 2），
 *        新增此类写法时必须同步扩展本扫描器，而不是放宽断言。
 *
 * 4. 记录型静态方法 AuditLog.recordLogin（内部固定 login_success / login_failed）
 *    与 recordSensitiveAction 的字面量第 3 参：前者 action 由方法**自身**决定，字面量确实
 *    写在 writeStatics 源码里，但**不在任何 `AuditLog.xxx(` 调用点里**——所以它不是
 *    "天然被第 2 条覆盖"，而是原实现的一个整套件全绿的缺口（F-201，见上面第 1 条的实测）。
 *    现已由第五类形态 `this.create(` 纳入；正向断言见「静态方法自身决定的 action 在集合里」。
 */

// "什么算写入"的唯一实现放在 helpers 里，与反向可达性闸（auditActionReachability）共用：
// 两处各写一份判据时，对账闸的结论只强于"两个实现都同意"的那部分——实测过分叉两次
// （正向看不见模型静态方法自身的 action；反向把 countDocuments 的只读上下文算成写入）。
// 判据口径与文件头一致，改动前先读那边。
const {
  scanWriteSites,
  scanActionLiterals,
  isInsideComment,
  resolveActionExpr,
  forwardingReason,
  collectEarlyRejectionAliases,
} = require('../helpers/auditWriteSites');

describe('审计 action 白名单对账（P1-11 / P3-61）', () => {
  /**
   * 注释识别的判据自证 + 反噬检查。
   *
   * 触发本用例的真实事件：constants/audit.js 里解释"method 越枚举为什么等于丢整条审计"的
   * 注释写了 `AuditLog.record()`，扫描器把它当成一个解析不出 action 的调用点，
   * 于是**一条注释让全仓 CI 变红**——而它唯一的便宜修法是删注释。
   *
   * 因此这组断言两向都要立：注释里的调用点跳过，**代码里的同形调用点不得跳过**。
   * 后者是本修补的反噬面：一旦实现写成"含 record( 的行一律跳过"，
   * 真正的写入点就能藏在看似无害的行里逃出对账，那比原来的误报严重一个量级。
   */
  test('注释里的调用点跳过，代码里的同形调用点必须仍然算数', () => {
    const at = (text, token = 'AuditLog.record(') => text.indexOf(token) + 1;
    const hit = (text) => isInsideComment(text, at(text));

    // 1) 注释形态：行注释、块注释续行、缩进的 //
    expect(hit('// 直写路径 AuditLog.record()：错误进 catch')).toBe(true);
    expect(hit(' * 缓冲路径 AuditLog.record({action:"x"}) 会丢整条')).toBe(true);
    expect(hit('    // AuditLog.record(')).toBe(true);
    // 2) 行尾注释：起始符之后不算代码
    expect(hit('const x = 1; // 见 AuditLog.record(')).toBe(true);
    // 3) 代码形态：一律不得跳过（这是反噬面）
    expect(hit('  AuditLog.record({ action: "user_locked" })')).toBe(false);
    expect(hit("  const url = 'http://x'; AuditLog.record({})")).toBe(false);
    expect(hit('await AuditLog.record(\n  { action: "x" }\n)')).toBe(false);
  });

  test('src/ 实际写入的 audit action 全部在 AUDIT_LOG_ACTIONS 白名单内', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    const whitelist = new Set(AUDIT_LOG_ACTIONS);
    const { written, unresolved } = scanWriteSites();

    // 解析失败必须是硬失败：新写法不得悄悄逃出对账范围
    expect(unresolved).toEqual([]);

    const missing = [...written.keys()].filter((a) => !whitelist.has(a)).sort();
    expect(missing).toEqual([]);
    // 扫描有效性下限：若调用点识别逻辑失效（例如 token 改名），
    // written 会退化成空集而"对账通过"——用下限断言防这种静默失效
    expect(written.size).toBeGreaterThanOrEqual(30);
    expect(written.has('account_temp_locked')).toBe(true);
    // 反空心断言（2026-09-25）：action 走**局部常量**、且写入点是**内联 require** 的那条
    // （errorHandler 的截断更正事件）必须在集合里。缺了这条，上面那两处扩展等于没做——
    // 它当初正是同时躲过本对账与反向可达性，才让一个未登记的 action 双向判绿。
    expect(written.has('response_aborted_after_headers')).toBe(true);
    expect(written.get('response_aborted_after_headers').join(',')).toContain('errorHandler.js');
  });

  /**
   * 反空心断言（F-201）：第五类形态 `this.create(` 真在扫描范围内。
   *
   * 判据必须是"这条 action 来自 writeStatics"，而不是"集合非空"——上面 `written.size>=30`
   * 在扩展前后同样绿，它证明不了新形态生效。缺了这条，第五类形态可以整体失效而无人报错，
   * 与本文件头记录的 errorHandler 案例是同一类失效（扩展做了、但没钉住）。
   */
  test('静态方法自身决定的 action（recordLogin 三元）在对账集合里', () => {
    const { written, unresolved } = scanWriteSites();
    expect(unresolved).toEqual([]);
    for (const a of ['login_success', 'login_failed']) {
      expect(written.has(a)).toBe(true);
      // 且必须由 writeStatics 自身贡献——别的文件里恰好有同名字面量不算数
      expect(written.get(a).join(',')).toContain('auditLogWriteStatics.js');
    }
  });

  /**
   * `recordEarlyRejection` 的**一跳转发别名**不得成为对账盲区（F-201 同类，再下一层）。
   *
   * queryLimit.js 把审计写入包在 `recordQueryRejection(req, meta)` 里（延迟 require 防环），
   * 于是它的 action 字面量既不落在 `recordEarlyRejection(` 的字面量收集中、
   * 也不落在 WRITE_CALLS 里。实测把 `'query_param_rejected'` 改名后正向对账仍全绿——
   * 而这条 action 是"未认证请求阶段的 NoSQL 探测/超长参数被挡"的唯一留痕。
   *
   * 注：written 里的调用点标签是**转发目标**（security.js 里 `AuditLog.record` 那处），
   * 不是别名处；别名由扫描器从源码发现并钉在下面的精确清单里，不手抄名字。
   * 清单里两条都得列：originCheck.js:29 是同名字 `recordEarlyRejection` 的同款一跳包装
   * （它对 action 收集是幂等的——扫描按名字全文匹配，基础名已经覆盖它的调用点），
   * 但"幂等"不等于"可以不出现在清单里"：清单的意义是**新增一个转发包装必须当场显式判定**。
   */
  test('经一跳别名写入的 action 在对账集合里', () => {
    const { written, unresolved } = scanWriteSites();
    expect(unresolved).toEqual([]);
    expect([...collectEarlyRejectionAliases()].sort()).toEqual([
      'recordEarlyRejection',
      'recordQueryRejection',
    ]);
    expect(written.has('query_param_rejected')).toBe(true);
  });

  /**
   * 转发点账本：跳过必须留名，新增转发点要显式改判。
   *
   * `this.create(` 纳入后，同文件里另有两处**转发型**写法本处没有字面量可解析
   * （record 把入参对象整体转交、recordSensitiveAction 用 `{ action, ... }` 简写）。
   * 把它们记成一份精确清单而不是"识别到转发就跳过"：清单变化 = 有人新开了一个
   * action 不由本文件决定的写入口，那处调用方是否真的被前四类形态覆盖，必须当场核对。
   */
  test('转发型静态方法写入点：精确清单（跳过有主，不得成为无界逃逸口）', () => {
    const { forwarded } = scanWriteSites();
    expect([...forwarded].sort()).toEqual([
      'src/models/auditLogWriteStatics.js<record>:forward-arg',
      'src/models/auditLogWriteStatics.js<recordSensitiveAction>:shorthand-action',
    ]);
  });

  /**
   * forwardingReason 自身的判据自证（含反噬面）。
   *
   * 只测正向放行不测反向拒绝，等于把"跳过转发"写成一个可以随手扩大的口子：
   * `{ action: someVar }` 这类**解析不出字面量的具名属性**必须仍判 null（→ unresolved 硬失败），
   * 否则新增一个未登记的 action 就能借"转发"名义双向隐身。
   */
  test('转发识别只认两种转发形态，解析不出的具名属性仍须判 null', () => {
    // 1) 正向：两种转发形态
    expect(forwardingReason('modelStatic', 'entry', null)).toBe('forward-arg');
    expect(forwardingReason('modelStatic', '{ action, category }', null)).toBe('shorthand-action');
    // 2) 反噬面：不是转发、且解不出字面量 → null（调用方走 unresolved 硬失败）
    expect(forwardingReason('modelStatic', '{ action: someVar }', 'someVar')).toBeNull();
    expect(forwardingReason('modelStatic', '{ action, other }', "'lit'")).toBeNull();
    // 3) 反噬面：非 modelStatic 一律不认转发（AuditLog.record(entry) 仍须报 unresolved）
    expect(forwardingReason('record', 'entry', null)).toBeNull();
    // 4) 混合形态不得蒙混：action 简写之外还有别的表达式
    expect(forwardingReason('modelStatic', '{ note: f(a, b) }', null)).toBeNull();
  });

  test('常量间接层解析：只认同名的字符串 const，解不出仍须返回 null（不得凭空造 action）', () => {
    const ctx = { ALERT_TYPES: {}, earlyRejectionActions: [] };
    expect(
      resolveActionExpr('ACTION', ctx, "const ACTION = 'x_aborted';\npush({ action: ACTION });")
    ).toEqual(['x_aborted']);
    // 非字符串 const 不得被当成 action（否则一个计数器名就能伪造出"已登记的写入点"）
    expect(
      resolveActionExpr('ACTION', ctx, 'const ACTION = 7;\npush({ action: ACTION });')
    ).toBeNull();
    // 没有任何定义的标识符仍然 null ⇒ 调用方走 unresolved 硬失败，而不是静默跳过
    expect(resolveActionExpr('NEVER_DEFINED_HERE', ctx, "const ACTION = 'x';")).toBeNull();
  });

  test('P1-11 回归：account_temp_locked 在库可查（validateEnum 白名单命中）', () => {
    const { AUDIT_LOG_ACTIONS } = require('../../constants/audit');
    expect(AUDIT_LOG_ACTIONS).toContain('account_temp_locked');
    // 同一病症的第二次（2026-09-25 审计发现）：截断更正事件确实写进了库，但 action 没登记
    // ⇒ 按 action 筛选直接 400，"这次导出被截断了"这条唯一线索查不出来。
    // 它之所以能双向判绿躲过本对账与可达性用例，是因为写入点用了内联 require + 局部常量；
    // 上面两条断言把这两种形态都钉成了可扫描范围。
    expect(AUDIT_LOG_ACTIONS).toContain('response_aborted_after_headers');
  });

  /**
   * 回球闸的排除清单（F-203）。
   *
   * 文件头第 3 条把"子文档 action / WebSocket payload / helmet 选项"列为排除项，
   * 理由是"不是 AuditLog 写入，同上不匹配"——这句话**原先只是描述**：它断言的是
   * `WRITE_CALLS` 认不出这些形态，而一旦哪天某个形态被认出来了、或者一个真正的审计
   * 写入长得像它们，没有任何东西会发现。本清单把这句话变成可核对的账：
   *   · 方向一：代码里出现的每个 `action:'字面量'`，要么其 action 在 `written` 里
   *     （说明确实有写入形态认领它），要么逐条出现在下面并写明家族与出处；
   *   · 方向二：清单里的条目若源码不再出现 ⇒ `toEqual` 同样转红，清单不会烂成僵尸。
   * 新增一条必须写清它为什么不是审计写入——这正是"排除"本来该有的成本。
   */
  const NOT_AUDIT_ACTION_LITERALS = [
    ['src/controllers/roleController.js', 'created', 'ws', ':170 WebSocket 权限同步广播载荷'],
    ['src/controllers/roleController.js', 'deleted', 'ws', ':274 同上'],
    ['src/controllers/rolePermissionController.js', 'permissions-cloned', 'ws', ':189/:199 同上'],
    ['src/controllers/rolePermissionController.js', 'permissions-updated', 'ws', ':269/:280 同上'],
    ['src/controllers/userController.js', 'roles-assigned', 'ws', ':763 同上'],
    ['src/middleware/security.js', 'deny', 'helmet', ':103 helmet frameguard 选项'],
    ['src/services/AlarmService.js', 'alarm_received', 'subdoc', ':158 FireAlarm.processLog'],
    ['src/services/AlarmService.js', 'dispatched', 'subdoc', ':228 同上'],
    ['src/services/AlarmService.js', 'arrived', 'subdoc', ':252 同上'],
    ['src/services/AlarmService.js', 'resolved', 'subdoc', ':274 同上'],
    ['src/services/AlarmService.js', 'marked_false_alarm', 'subdoc', ':311 同上'],
    ['src/services/AlarmService.js', 'cancelled', 'subdoc', ':346 同上'],
    ['src/services/InspectionService.js', 'started', 'subdoc', ':268 巡检状态流转子文档'],
    ['src/services/InspectionService.js', 'completed', 'subdoc', ':305 同上'],
    ['src/services/InspectionService.js', 'cancelled', 'subdoc', ':377 同上'],
    ['src/services/userService.js', 'handler_released', 'subdoc', ':218 FireAlarm.processLog'],
  ];

  test('回球闸：代码里每个 action 字面量要么被写入形态认领，要么在排除清单里（F-203）', () => {
    const { written } = scanWriteSites();
    const literals = scanActionLiterals();
    // 反向对照：这条闸不是空转——它扫到的字面量远多于写入形态认领的那些
    expect(literals.length).toBeGreaterThan(written.size);
    const unclaimed = literals.filter((l) => !written.has(l.action));
    const pairs = [...new Set(unclaimed.map((l) => `${l.file} :: ${l.action}`))].sort();
    expect(pairs).toEqual(NOT_AUDIT_ACTION_LITERALS.map(([f, a]) => `${f} :: ${a}`).sort());
    // 每条都要有家族与出处；家族计数把"清单只是抄了一遍"钉死
    const tally = { ws: 0, helmet: 0, subdoc: 0 };
    NOT_AUDIT_ACTION_LITERALS.forEach(([, , family, why]) => {
      expect(tally).toHaveProperty(family);
      expect(why).toMatch(/:\d{2,}/); // 出处必须落到行号
      tally[family] += 1;
    });
    expect(tally).toEqual({ ws: 5, helmet: 1, subdoc: 10 });
  });

  /**
   * 回球闸的牙（临时夹具，双向对照）。
   *
   * 为什么必须实测而不是只在清单上写理由：主扫描器对下面四种形态的处理是**静默**的
   * （实测 2026-09-26，子代理给出形态、本轮在真实扫描器上复现）——它们既不进 written、
   * 也不进 unresolved、更不进 forwarded，于是"写进审计集合却不在白名单"这一整类
   * （P1-11 的原始病症）从两侧都查不出来。回球闸只看"这一行有代码"，不看注释判定，
   * 因为注释判定本身可被伪造（行内正则字面量的 `//` 会被当成行尾注释）。
   */
  test('回球闸的牙：主扫描器静默漏掉的四种形态，回球结果必须全部看见', () => {
    const fs = require('fs');
    const path = require('path');
    const os = require('os');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zzqoder-backstop-'));
    try {
      fs.writeFileSync(
        path.join(dir, 'fixture.js'),
        [
          "const AuditLog = require('../models/auditLog');",
          "AuditLog.insertMany([{ action: 'zz_probe_insertmany' }]);",
          // 行内正则字面量里的 // 会让 isInsideComment 误判成注释 ⇒ 同行的真实写入逃出主扫描器
          "const isAbs = /^https?:\\/\\//.test(url); AuditLog.record({ action: 'zz_probe_regex' });",
          // 数组实参：主扫描器只读第一个对象字面量
          "auditBuffer.push([{ action: 'zz_probe_first' }, { action: 'zz_probe_second' }]);",
          "// action: 'zz_probe_full_line_comment'",
          "/* action: 'zz_probe_block_comment' */",
        ].join('\n'),
        'utf8'
      );
      // ① 回球面：4 个代码形态全部看见，两条注释形态全部不看见
      expect(scanActionLiterals(dir).map((l) => l.action)).toEqual([
        'zz_probe_insertmany',
        'zz_probe_regex',
        'zz_probe_first',
        'zz_probe_second',
      ]);
      // ② 主扫描器对照：同一个夹具里它只认领 1 个，且不产生任何 unresolved/forwarded
      //    ⇒ 漏检是静默的（这正是回球闸存在的理由）
      const { written, unresolved, forwarded } = scanWriteSites(dir);
      expect([...written.keys()]).toEqual(['zz_probe_first']);
      expect(unresolved).toEqual([]);
      expect(forwarded).toEqual([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
