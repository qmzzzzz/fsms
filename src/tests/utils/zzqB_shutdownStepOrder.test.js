'use strict';

/**
 * 关停链的步骤序：SIEM 转发缓冲的排空必须是**最后一步**
 *
 * 【这条性质从哪来】`src/index.js` 里那一步的注释自己写着"放在链尾是**有意的**：
 * 上面每一步自己写的日志（"MongoDB 连接已关闭"、审计未排空的 error）都还压在这个
 * 缓冲里，越早排就越少送到"，并给出保留额度取 0 的理由（后面没有要保住的步骤了）。
 * 也就是说：文档里有一条不变式，代码里没有任何一处兑现它。
 *
 * 【既有覆盖缺的那一格】关停链上另有两处判据扫同一段源码，都是**位置无关**的：
 *   · 排空调用在优雅关闭区间内出现 1 次（计数）、且紧跟 `stepAllowMs(0)`（相邻性）；
 *   · 区间内 `stepAllowMs(` 出现 6 次（步骤总数）。
 * 于是"在排空之后再加一步清理"和"把排空搬到链首"这两种真实演进都抓不到——计数不变、
 * 相邻性不变，只是新步骤写的日志再也送不到 SIEM。链上最近两次扩步骤（关 Redis、关 Mongo）
 * 正是"在某步之后又插一步"的形态，所以这不是假想对手。
 *
 * 【判据口径】只能建立在"剥掉注释的代码视图"上：③ 合成了一份"真实调用被搬走、
 * 尾部注释里留着同形文本"的源码，它在文本视图上完全合格。这与仓内其它源码位置闸同源。
 *
 * 【为什么是源码判据而不是端到端】端到端要起应用、灌假 SIEM sink、发 SIGTERM 再比对
 * "链上后几步的日志到没到"，价值更高但依赖端口/数据库与共机负载，本轮不做；
 * 这里先把"序"钉住，端到端留给能独占机器的窗口（差异已记入交付台账）。
 */

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.join(__dirname, '..', '..', '..');
const DRAIN_STEP = "await runStep('排空 SIEM 日志转发缓冲'";
const NORMAL_EXIT = 'return exitAfterFlush(0, { delayMs: 500 });';

/** 与关停链其它判据同源：注释换成等长空白，行号与**字符位置单调性**才有意义 */
function jsCodeOnly(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .split('\n')
    .filter((l) => !/^\s*\/\//.test(l))
    .map((l) => l.replace(/\/\/[^\n]*/g, ' '))
    .join('\n');
}

const readIndex = () => fs.readFileSync(path.join(REPO_ROOT, 'src/index.js'), 'utf8');

/** 优雅关闭那段：从 `const gracefulShutdown` 到 `const startServer`（与既有区间闸同边界） */
function gracefulRegion(view) {
  const from = view.indexOf('const gracefulShutdown');
  const to = view.indexOf('const startServer');
  expect(from).toBeGreaterThan(-1);
  expect(to).toBeGreaterThan(from);
  return view.slice(from, to);
}

/**
 * 判据拆成可分别失败的分量：②③ 的合成反例要指出**哪一格**红，
 * 只给一条整体布尔的话，反例命中了别的分支也算"验证通过"。
 */
function positions(region) {
  const steps = [...region.matchAll(/await runStep\(/g)].map((m) => m.index);
  const lastStep = steps.length ? steps[steps.length - 1] : -1;
  const exitAt = region.indexOf(NORMAL_EXIT);
  return {
    stepCount: steps.length,
    exitAt,
    lastStepIsDrain: lastStep >= 0 && region.startsWith(DRAIN_STEP, lastStep),
    exitFollowsLastStep: exitAt > lastStep,
    lastStepText: region.slice(lastStep, lastStep + 40).replace(/\s+/g, ' '),
  };
}

/** 摘出真实那一步的完整调用（从 `await runStep(` 到它的收尾 `  });`），供反例搬动 */
function extractDrainStep(raw) {
  const from = raw.indexOf(DRAIN_STEP);
  expect(from).toBeGreaterThan(-1);
  const to = raw.indexOf('\n  });', from);
  expect(to).toBeGreaterThan(from);
  const step = raw.slice(from, to + '\n  });'.length);
  expect(step).toContain('bestEffortDrain'); // 前提：摘到的确实是那一步
  return { from, to: to + '\n  });'.length, step };
}

describe('优雅关闭链的步骤序：SIEM 排空必须排在最后', () => {
  test('① 真实源码：链尾那一步就是 SIEM 排空，其后只有正常退出语句', () => {
    const p = positions(gracefulRegion(jsCodeOnly(readIndex())));
    // 前提自证：判据不是空集恒真（步骤数、退出点唯一性都先站住）
    expect(p.stepCount).toBeGreaterThanOrEqual(6);
    expect(jsCodeOnly(readIndex()).match(/exitAfterFlush\(0/g) || []).toHaveLength(1);

    expect(p.lastStepIsDrain).toBe(true);
    expect(p.exitFollowsLastStep).toBe(true);
    expect(p.lastStepText).toContain('排空 SIEM');
  });

  test('② 反例（只在内存里改，不落盘）：排空之后再挂一步、或把它自己搬到链首，都必须是红', () => {
    const raw = readIndex();
    expect(positions(gracefulRegion(jsCodeOnly(raw))).lastStepIsDrain).toBe(true); // 对照臂

    // 走法 A：在排空之后追加一步会写日志的清理器（最常见的演进形态）
    const appended = raw.replace(
      NORMAL_EXIT,
      "await runStep('停止某项新清理器', () => {\n    logger.info('新清理器已停止');\n  });\n  " +
        NORMAL_EXIT
    );
    expect(appended).not.toBe(raw);
    const pA = positions(gracefulRegion(jsCodeOnly(appended)));
    expect(pA.lastStepIsDrain).toBe(false);
    expect(pA.lastStepText).toContain('停止某项新清理器'); // 红在对的原因上

    // 走法 B：把排空搬到 WebSocket 之后 —— 调用形状一字未改，
    // 于是"区间内出现 1 次"和"紧跟 stepAllowMs(0)"两条既有闸都不会红
    const { step, from, to } = extractDrainStep(raw);
    const withoutStep = raw.slice(0, from) + raw.slice(to);
    const moved = withoutStep.replace(
      "  await runStep('关闭 HTTP 服务器'",
      `  ${step}\n  await runStep('关闭 HTTP 服务器'`
    );
    expect(moved).not.toBe(withoutStep);
    expect(moved).not.toBe(raw);
    const pB = positions(gracefulRegion(jsCodeOnly(moved)));
    expect(pB.lastStepIsDrain).toBe(false);
    expect(pB.lastStepText).toContain('关闭 MongoDB 连接');
    // 搬动没有改变步骤总数 ⇒ 计数型判据对它无感的实证（不是我推断的）
    expect(pB.stepCount).toBe(positions(gracefulRegion(jsCodeOnly(raw))).stepCount);
  });

  test('③ 注释骗不过：真实调用被搬走、尾部注释留着同形文本 ⇒ 文本视图绿、代码视图红', () => {
    const raw = readIndex();
    // 先取走那一步，再在退出语句前补一条**注释**形态的同形调用（运维读源码时看得见）
    const { step, from, to } = extractDrainStep(raw);
    const tail = raw.slice(to);
    const commented =
      raw.slice(0, from) +
      tail.replace(NORMAL_EXIT, `/* 链尾：${step.replace(/\n/g, ' ')} */\n  ${NORMAL_EXIT}`);
    // 把被取走的那一步放到 WebSocket 之后，构造出"实际提前了、注释说还在链尾"的源码
    const moved = commented.replace(
      "  await runStep('关闭 HTTP 服务器'",
      `  ${step}\n  await runStep('关闭 HTTP 服务器'`
    );
    const regionText = gracefulRegion(moved);
    expect(regionText).not.toBe(gracefulRegion(raw));
    // 文本视图被骗：最后一个 runStep 是注释里那条排空 ⇒ 两个分量都合格
    const pText = positions(regionText);
    expect(pText.lastStepIsDrain).toBe(true);
    expect(pText.exitFollowsLastStep).toBe(true);
    // 代码视图不被骗：注释剥掉后链尾回到真实的那一步（已被搬到 WebSocket 之后）
    const pCode = positions(gracefulRegion(jsCodeOnly(moved)));
    expect(pCode.lastStepIsDrain).toBe(false);
    expect(pCode.lastStepText).toContain('关闭 MongoDB 连接');
  });
});
