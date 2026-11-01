'use strict';

/**
 * G-1 同型普查（r21-c 门禁缺口）：**服务层**的「参数是某张表的键」裸下标查表
 *
 * 守的是什么：`reportTargetService.search({ type })` 对**任意** `type` 字符串都不得抛错。
 * 契约写在 `src/services/reportTargetService.js:73`：「未知类型返回空集，不抛错」。
 *
 * 为什么这条要单独存在（G-1 的原话是「加一格原型链键即可」，但那只覆盖了控制器）：
 * M-1 的修复（`sensitive.js:323` 用 `Object.hasOwn`）让**控制器**不再把原型链键传进来，
 * 于是控制器侧的用例（`reportTargetCandidates.test.js:274`）现在是绿的。
 * 但**同一个形状在下一层还在**：`reportTargetService.js:80` 是 `const kind = KINDS[type]; if (!kind) return [];`
 * ——`KINDS` 是普通对象字面量，`KINDS['constructor']` 取到 `Object.prototype.constructor`（truthy）
 * ⇒ `!kind` 兜底失效 ⇒ `kind.model.find(...)` 抛 `TypeError`。
 * 现在没有活的调用方会传原型链键（控制器已挡住），所以它不是当前可达的 500；
 * 但这份契约是本模块**自己写明的**，违反契约的是它自己。任何新调用方（脚本/CLI/下一个端点）
 * 直接复用 `search()` 就会把这层缺陷变成真 500。
 *
 * 实跑证据（本文件 ③ 摘掉 `.failing` 后的真实输出，见报告）：
 *   `TypeError: Cannot read properties of undefined (reading 'find')` × 5 个原型链键，
 *   `inspection`（非原型链的未知类型）正常返回 `[]` ⇒ 缺陷只在原型链键上，不是「什么未知类型都抛」。
 *
 * 三条腿：
 *   ① 反向对照（现在就该绿）：真类型 user 走真模型查询、未知类型 inspection 返回空集不抛；
 *   ② 反向对照（现在就该绿）：`KINDS` 里确实只有 3 个键——证明 ① 的「空集」不是「表是空的」造的；
 *   ③ 原型链键必须返回空集而不是抛错（**2026-11-02 已修：`reportTargetService.js:83` 改用 `Object.hasOwn`**）。
 *
 * ③ 的来历（**不要删这一段**：否则后人不知道它曾经是红的、红在哪）：
 * 它以 `test.failing` 记账约 20 分钟，期间摘掉 `.failing` 跑出的真实失败原文是：
 *
 *   ● G-1 服务层裸下标查表 › ③ 原型链键…必须返回空集而不是抛 TypeError
 *     expect(received).toEqual(expected) // deep equality
 *     - Expected  - 5
 *     + Received  + 5
 *       Array [
 *     -   "constructor=ok:[]",
 *     +   "constructor=THROW:TypeError",
 *         ...（toString / valueOf / __proto__ / hasOwnProperty 同形）
 *   Tests:       1 failed, 2 passed, 3 total
 *
 * 为什么要留这段原文：`.failing` 把红变成绿，于是它会把**任何**失败都吸收掉——包括夹具自己坏了。
 * 修完之后「它现在绿」这件事本身不证明任何东西；只有当初那条失败原文能证明这条判据确实看过这个缺陷。
 * 口径（lead 立为团队口径）：**每写一条 `.failing`，必须存一份「摘掉后」的真实失败原文，并钉死失败原因**
 * （本例钉的是 `THROW:TypeError`，不是笼统的「它红了」）。
 */

const mongoose = require('mongoose');

const svc = require('../../services/reportTargetService');

/** 原型链上真实存在、且 `TABLE[key]` 会取到 truthy 值的那些键 */
const PROTOTYPE_KEYS = ['constructor', 'toString', 'valueOf', '__proto__', 'hasOwnProperty'];

beforeAll(async () => {
  if (mongoose.connection.readyState === 0) await mongoose.connect(process.env.MONGODB_URI);
});
afterAll(async () => {
  if (mongoose.connection.readyState !== 0) await mongoose.connection.close();
});

describe('G-1 服务层裸下标查表：未知 type 必须返回空集，不得抛错', () => {
  test('① 反向对照：真类型走真查询、非原型链的未知类型返回空集（这条绿才说明夹具没坏）', async () => {
    // 真类型：查询真的打到库上（空库 ⇒ []）
    await expect(svc.search({ type: 'user', filter: {}, keyword: '', limit: 5 })).resolves.toEqual(
      []
    );
    // 非原型链的未知类型：契约明写「返回空集，不抛错」，现在确实如此
    await expect(
      svc.search({ type: 'inspection', filter: {}, keyword: '', limit: 5 })
    ).resolves.toEqual([]);
    await expect(
      svc.search({ type: undefined, filter: {}, keyword: '', limit: 5 })
    ).resolves.toEqual([]);
  });

  test('② 反向对照：KINDS 恰好是 user/device/alarm 三键（① 的空集不是「表是空的」造成的）', () => {
    expect(Object.keys(svc.KINDS).sort()).toEqual(['alarm', 'device', 'user']);
  });

  test('③ 原型链键（constructor/toString/valueOf/__proto__/hasOwnProperty）必须返回空集而不是抛 TypeError', async () => {
    const outcomes = [];
    for (const type of PROTOTYPE_KEYS) {
      try {
        const r = await svc.search({ type, filter: {}, keyword: '', limit: 5 });
        outcomes.push(`${type}=ok:${JSON.stringify(r)}`);
      } catch (err) {
        outcomes.push(`${type}=THROW:${err.constructor.name}`);
      }
    }
    // 逐条列出，不写成「整组一个 toEqual」——否则漏了哪一条看不出来
    expect(outcomes).toEqual(PROTOTYPE_KEYS.map((t) => `${t}=ok:[]`));
  });
});
