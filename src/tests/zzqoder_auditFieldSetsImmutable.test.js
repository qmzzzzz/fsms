'use strict';

/**
 * 审计链的历史字段清单必须**不可变**
 *
 * `utils/auditChainPayload.js` 自己记录过一次事故：v3 曾写成
 * `const PAYLOAD_FIELDS_V3 = PAYLOAD_FIELDS_V2`（同一引用），
 * 于是"给 v2 追加一个字段"就会静默改写 v3 的语义——
 * 历史记录的哈希再也复算不出来，表现为**大面积假篡改告警**。
 * 防篡改链最坏的失败形态不是"漏报"而是"把完好链路报成被篡改"：
 * 运维的唯一处置手段是整库重签，而重签本身会销毁"当年是什么样"的证据。
 *
 * 注释和 review 防不住第三次，`Object.freeze` 防得住：
 * 清单内容从此在物理上无法被 push/splice 改动。
 * 本用例同时钉住三件事，缺一就会退化成"看着严证实则空转"：
 *   ① 四份清单都处于 frozen 状态；
 *   ② 在严格模式调用方里改动它们必须抛 TypeError，且抛完之后内容一字未变；
 *   ③ **反向前提**：同一份未冻结的副本 push 必须成功——
 *      否则 ② 可能只是因为"push 永远不抛"而假绿。
 */

const {
  PAYLOAD_FIELDS_V1,
  PAYLOAD_FIELDS_V2,
  PAYLOAD_FIELDS_V3,
  PAYLOAD_FIELDS_V4,
  canonicalPayload,
  CURRENT_PAYLOAD_VERSION,
} = require('../utils/auditChainPayload');

const ALL_SETS = {
  V1: PAYLOAD_FIELDS_V1,
  V2: PAYLOAD_FIELDS_V2,
  V3: PAYLOAD_FIELDS_V3,
  V4: PAYLOAD_FIELDS_V4,
};

describe('zzqoder 审计链字段清单不可变', () => {
  test('四份清单全部 frozen', () => {
    for (const [name, list] of Object.entries(ALL_SETS)) {
      expect({ name, frozen: Object.isFrozen(list) }).toEqual({ name, frozen: true });
    }
  });

  test.each(Object.keys(ALL_SETS))('%s：改动清单必须抛 TypeError 且内容不变', (name) => {
    const list = ALL_SETS[name];
    const snapshot = list.slice();
    expect(() => {
      list.push(`zz-injected-${name}`);
    }).toThrow(TypeError);
    expect(list).toEqual(snapshot);
  });

  test('反向前提：未冻结的同一份清单 push 会成功（证明上一条不是空转）', () => {
    const loose = [...PAYLOAD_FIELDS_V2];
    expect(Object.isFrozen(loose)).toBe(false);
    loose.push('zz-allowed');
    expect(loose).toContain('zz-allowed');
    expect(PAYLOAD_FIELDS_V2).not.toContain('zz-allowed');
  });

  test('版本清单必须是互不相同的快照（v3 事故的直接回归）', () => {
    expect(PAYLOAD_FIELDS_V3).not.toBe(PAYLOAD_FIELDS_V2);
    expect(PAYLOAD_FIELDS_V4).not.toBe(PAYLOAD_FIELDS_V3);
    expect(PAYLOAD_FIELDS_V3).toEqual(PAYLOAD_FIELDS_V2);
    expect(PAYLOAD_FIELDS_V4.slice(0, PAYLOAD_FIELDS_V3.length)).toEqual(PAYLOAD_FIELDS_V3);
  });

  test('v4 新增的四字段只属于 v4（否则历史口径又被悄悄改写）', () => {
    const added = ['targetType', 'targetId', 'dataType', 'description'];
    for (const f of added) {
      expect(PAYLOAD_FIELDS_V4).toContain(f);
      expect(PAYLOAD_FIELDS_V2).not.toContain(f);
      expect(PAYLOAD_FIELDS_V3).not.toContain(f);
    }
  });

  test('分派表逐版稳定：同一文档按 1/2/3/4 复算得到四个不同结果', () => {
    const doc = {
      timestamp: new Date('2026-09-19T00:00:00.000Z'),
      action: 'user_login',
      category: 'auth',
      username: 'u1',
      ip: '10.0.0.1',
      path: '/api/auth/login',
      statusCode: 200,
      body: { a: 1 },
      riskLevel: 'low',
      riskFactors: ['x'],
      description: '取证要看的值',
    };
    const digests = [1, 2, 3, CURRENT_PAYLOAD_VERSION].map((v) => canonicalPayload(doc, v));
    // v2 与 v3 字段集相同 ⇒ 这两版必然同串（这是设计，不是缺陷）；
    // v1 与 v4 都必须与它们不同 ⇒ 任何一版被悄悄改写都会在这里现形。
    expect(digests[1]).toEqual(digests[2]);
    expect(digests[0]).not.toEqual(digests[1]);
    expect(digests[3]).not.toEqual(digests[1]);
    // v4 的串必须真的带上那四个新字段（防止"清单加了、payload 没进"的假收紧）
    expect(digests[3]).toContain('description');
    expect(digests[1]).not.toContain('description');
  });

  test('缺省版本就是当前写入版本（写入端与校验端不许各自理解缺省）', () => {
    const doc = { timestamp: new Date('2026-01-01T00:00:00.000Z'), action: 'a', body: {} };
    expect(canonicalPayload(doc)).toEqual(canonicalPayload(doc, CURRENT_PAYLOAD_VERSION));
    // hashVersion 缺失时校验端按 v1 口径（`doc.hashVersion || 1`），
    // 这里钉住"缺省 ≠ 历史口径"，避免有人把两处的缺省值改成一样
    expect(canonicalPayload(doc)).not.toEqual(canonicalPayload(doc, 1));
  });
});

/**
 * F-153：快照必须真的被读
 *
 * 本文件前面几行钉的是"清单本身不可变、且互不相同的快照"。但复算分派原先写成
 * `canonicalPayloadV2(doc, PAYLOAD_FIELDS_V2)`，v3 记录复算时读的还是 V2 ——
 * `PAYLOAD_FIELDS_V3` 在生产代码里零读取点。那意味着"独立快照"的全部防护
 * （给 V2 加字段不得改写 v3 语义）只是声明，没被任何一行代码执行。
 * 取值层面的相等（V3 toEqual V2）证不出这件事，所以这里钉**写法**，
 * 并按本仓纪律给判据自身配反面对照。
 */
describe('F-153：v3 复算必须读 V3 快照（分派未读＝承诺失效）', () => {
  const fs = require('fs');
  const path = require('path');
  const SRC = path.join(__dirname, '../utils/auditChainPayload.js');
  const code = fs
    .readFileSync(SRC, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');

  const DISPATCH =
    /version >= 2\s*\)?\s*return canonicalPayloadV2\(\s*doc,\s*version >= 3 \? PAYLOAD_FIELDS_V3 : PAYLOAD_FIELDS_V2\s*\)/;

  test('分派里 v3 分支引用的是 PAYLOAD_FIELDS_V3', () => {
    expect(code).toMatch(DISPATCH);
  });

  test('反面对照：退回"v2/v3 同读一份 V2"的原始写法会被上一条判红（上一条不是空跑）', () => {
    const laundered = code.replace(
      /canonicalPayloadV2\(\s*doc,\s*version >= 3 \? PAYLOAD_FIELDS_V3 : PAYLOAD_FIELDS_V2\s*\)/,
      'canonicalPayloadV2(doc, PAYLOAD_FIELDS_V2)'
    );
    expect(laundered).not.toBe(code);
    expect(laundered).not.toMatch(DISPATCH);
  });

  test('行为零变化：V3 与 V2 内容相等，所以 v2/v3 记录的既有哈希一字不动', () => {
    // 这一条是"本次改动不迁移历史数据"的证据；若哪天 V3 真的偏离 V2，
    // 它会红，届时必须走重签流程而不是让复算口径悄悄分叉。
    const doc = {
      timestamp: new Date('2026-03-04T05:06:07.008Z'),
      action: 'a',
      body: {},
      params: {},
      query: {},
    };
    expect(canonicalPayload(doc, 2)).toEqual(canonicalPayload(doc, 3));
    expect(canonicalPayload(doc, 3)).not.toEqual(canonicalPayload(doc, 4));
  });
});
