/**
 * 计数表容量淘汰（2026-09-30）
 *
 * 独立成文件而不是并进 rateLimitEscalation.test.js：容量上限是**加载期**从环境变量
 * 取的（CC_ESCALATION_MAX_TRACKED），而那个文件在顶层就 require 了被测模块——
 * 同一进程里没法先设 env 再 require。与 earlyRejectionRateLimitedAllSurfaces.test.js
 * 的处理同构（它也是「设 env 必须早于 require」）。
 *
 * 为什么单独钉：这条性质**没有任何报错就会静默失效**。把淘汰换回 `clear()`
 * 之后，全部测试仍然是绿的——计数表只是偶尔被清空，而清空本身不抛异常、不写审计。
 * 也就是说，攻击者"轮换 IP 把所有目标的计数归零"这条旁路，恰恰是最难被
 * 常规测试发现、也最值得机检的一类。
 *
 * 钉住的三条（方向相反，缺一条就有一半场景测不到）：
 *  1. 表大小不超过硬上限（不无界增长）；
 *  2. **不整体清空**：已有压力不能被一次溢出归零（`clear()` 形态必红）；
 *  3. 淘汰顺序由**安全价值**决定：压力最大的条目必须活下来。
 *     这条钉的是"按压力升序"而不是"按最旧优先"——后者同样是一条旁路：
 *     攻击者用新 IP 就能把"正要升级"的旧目标挤出表，而垃圾条目留在表里。
 */

process.env.CC_ESCALATION_MAX_TRACKED = '20';
process.env.CC_ESCALATION_EVICT_RATIO = '50';
process.env.CC_ESCALATION_THRESHOLD_ANON = '4';
process.env.CC_ESCALATION_THRESHOLD_VOLUME = '4';
process.env.CC_ESCALATION_THRESHOLD_AUTH = '4';

const escalation = require('../../services/rateLimitEscalation');

const CAP = Number(process.env.CC_ESCALATION_MAX_TRACKED);
const ANON = escalation.SIGNAL_CLASSES[escalation.CLASS_ANON_ABUSE].threshold;

/** 一次触发（隔离：本文件不 require middleware，不涉及封禁动作） */
const hit = (ip, limiter = 'captcha') => escalation.noteRateLimitHit({ ip }, limiter);

/** 取一个可用的文档网段内地址（与其它套件的 IPS 不重叠，避免审计行互相污染） */
const ipAt = (i) => `198.51.${Math.floor(i / 250)}.${(i % 250) + 1}`;

beforeEach(() => {
  escalation.resetForTest();
});

describe('计数表容量淘汰', () => {
  test('env 覆盖确实生效（否则本文件会在别的阈值下静默测错东西）', () => {
    expect(escalation.MAX_TRACKED_IPS).toBe(CAP);
    expect(escalation.EVICT_RATIO).toBe(50);
    expect(ANON).toBe(4);
  });

  test('表有界：超量灌入后旧条目被回收，且计数仍在继续工作', () => {
    const total = CAP * 3;
    for (let i = 0; i < total; i += 1) hit(ipAt(i));
    const lastIp = ipAt(total - 1);
    // 表仍在工作：最后一条必须还在（否则是"卡死"而不是"有界"）
    expect(escalation.peekIp(lastIp)).not.toBeNull();
    // 容量被真正回收：最早的条目必然已不在表内。
    // 全部条目压力相同（各 1 次），淘汰按 firstSeenMs 升序 —— 这是**并列时的 tiebreak**，
    // 不是"只按最旧淘汰"（那一条由下一条用例的反证覆盖）。
    expect(escalation.peekIp(ipAt(0))).toBeNull();
  });

  test('不整体清空：溢出不得把已有压力归零（clear() 形态必红）', () => {
    // 一个"正要升级"的 IP：压力 = 阀值 - 1 次触发
    const hot = ipAt(0);
    for (let i = 0; i < ANON - 1; i += 1) hit(hot);
    const before = escalation.peekIp(hot);
    expect(before[escalation.CLASS_ANON_ABUSE].total).toBe(ANON - 1);

    // 再灌满两倍容量的新 IP，触发淘汰
    for (let i = 1; i <= CAP * 2; i += 1) hit(ipAt(i));

    const after = escalation.peekIp(hot);
    expect(after).not.toBeNull();
    expect(after[escalation.CLASS_ANON_ABUSE].total).toBe(
      before[escalation.CLASS_ANON_ABUSE].total
    );
  });

  test('淘汰顺序由安全价值决定：压力最大的活下来（"按最旧优先"必红）', () => {
    // hot 最早进入（最旧）但压力最大；后面全是只有 1 次触发的噪声
    const hot = ipAt(0);
    for (let i = 0; i < ANON - 1; i += 1) hit(hot);
    const noise = [];
    for (let i = 1; i <= CAP * 2; i += 1) {
      noise.push(ipAt(i));
      hit(ipAt(i));
    }

    // hot 若按"最旧优先"淘汰，在第一轮就会被牺牲 —— 而它正是最接近升级的那条
    expect(escalation.peekIp(hot)).not.toBeNull();
    // 噪声确实被回收了一批（否则容量没有真正回收）
    const survivors = noise.filter((ip) => escalation.peekIp(ip) !== null).length;
    expect(survivors).toBeLessThan(noise.length);
  });

  test('已认证压力同样受保护（三类都算进打分，不能只看未认证两类）', () => {
    // 一个"已认证操作越界"的 IP：它不触发封禁，但最需要留证
    const hot = ipAt(0);
    for (let i = 0; i < ANON - 1; i += 1) hit(hot, 'strict');
    expect(escalation.peekIp(hot)[escalation.CLASS_AUTH].total).toBe(ANON - 1);

    for (let i = 1; i <= CAP * 2; i += 1) hit(ipAt(i), 'captcha');
    expect(escalation.peekIp(hot)).not.toBeNull();
  });
});
