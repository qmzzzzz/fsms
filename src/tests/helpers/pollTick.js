/**
 * 条件轮询的节拍原语（waitFor 家族共用）。
 *
 * 为什么在 helpers 而不是各测试文件里内联：noFixedSleepRatchet 的扫描面是 *.test.js，
 * `new Promise + setTimeout` 形态出现在测试文件里就会被「可 await 的固定睡眠」点名；
 * 而这里的节拍只服务于**有界条件轮询**（谓词命中即返回、超时即放弃），不是等待固定时长——
 * 两者失效形态不同（前者慢库下会误红，后者掩盖竞态），gate 抓的是后者。
 *
 * 25ms 而非 setImmediate：并行 worker 抢占下纯宏任务轮询会饿死（alarmView 同教训，
 * 见 attackDetectionIntegration.waitForRow 的注释）。
 */
const tick = (ms = 25) => new Promise((resolve) => setTimeout(resolve, ms));

module.exports = { tick };
