const {
  CURRENT_PAYLOAD_VERSION,
  canonicalPayload,
  computeHash,
  chainBatch,
} = require('../../utils/auditChain');
const { AUDIT_HTTP_METHODS } = require('../../constants/audit');

const AuditLog = require('../../models/AuditLog');

/**
 * 批量写入路径的不变量：算完哈希后，文档经 schema 铸造得到的「落库形态」必须仍能算回同一个哈希。
 *
 * 【这条不变量为什么单独测】批量路径（auditBuffer → chainBatch → insertMany）与逐条路径
 * （AuditLog.create → pre('save')）的差别是铸造发生的时机：逐条路径先铸造再算哈希，
 * 两侧必然同源；批量路径先对**普通对象**算哈希，insertMany 之后才铸造。只要 schema 里存在
 * 任何「改写值」的 set/子结构，被哈希的形态与落库的形态就会分叉——表现为**永久的 hash_mismatch**
 * （假篡改），且该记录的完整性保护从此静默失效：它已经是红的，真被改也照样红，
 * 而唯一的"补救"手段是整库重签（等于销毁取证价值）。
 *
 * 【本仓实际存在的改写器】AuditLog.js 的 method 带
 * `set: (value) => AUDIT_HTTP_METHODS.includes(value) ? value : undefined`
 * ——注释明确写着「TRACE / CONNECT 或任意自定义方法，Node 的 HTTP 解析器都收得下，
 * 而 app 级中间件在路由匹配之前就跑，所以它们确实会进审计层」。
 * 而 globalAudit 往缓冲里塞的是**未经枚举闸的 `req.method`**（security.js 的 persistAuditRecord），
 * 于是 `curl -X FOO` 一条请求就能造出一条永远核验不过的审计记录。
 */

/** 铸造 = insertMany 收到的那一步：同一条 schema、同一组 setter，只是不经 DB */
const castToStoredShape = (raw) => new AuditLog(raw).toObject({ getters: false, virtuals: false });

const baseRecord = (overrides) => ({
  action: 'login',
  category: 'auth',
  userId: '64f000000000000000000001',
  username: 'alice',
  ip: '127.0.0.1',
  path: '/api/auth/login',
  statusCode: 200,
  body: {},
  ...overrides,
});

/** 对「批量路径产出的一条文档」核验它自己：落库形态重算 == 落库哈希 */
function selfVerify(doc) {
  const stored = castToStoredShape(doc);
  const recomputed = computeHash(
    stored.prevHash,
    canonicalPayload(stored, CURRENT_PAYLOAD_VERSION)
  );
  return { stored, recomputed, same: recomputed === stored.hash };
}

describe('批量审计写入：被哈希的形态必须等于落库的形态', () => {
  it('枚举外的 HTTP 动词（TRACE / 自定义）不得让记录永久核验不过', () => {
    const docs = [
      baseRecord({ method: 'TRACE' }),
      baseRecord({ method: 'FOO' }),
      baseRecord({ method: 'get' }), // 小写同样不在枚举内
    ];
    chainBatch(docs, null);

    for (const doc of docs) {
      const { stored, recomputed } = selfVerify(doc);
      expect({ methodInDb: stored.method, same: recomputed === stored.hash }).toEqual({
        methodInDb: undefined, // schema 的 set 把它降成「不记 method」
        same: true, // 而哈希必须仍然是按「不记 method」算的那份
      });
    }
  });

  it('反向对照：枚举内的 7 个动词逐条都必须自洽，且 method 真的落库', () => {
    // 标题里的「7」必须有判据：本例是对 AUDIT_HTTP_METHODS 做 map，枚举被人删短时
    // 循环只是少跑几轮、断言仍然全绿（少一维却看不出来）。内容本身由
    // tests/models/AuditLog.test.js 的「单一事实来源」钉住，这里只钉基数。
    expect(AUDIT_HTTP_METHODS).toHaveLength(7);
    const docs = AUDIT_HTTP_METHODS.map((method) => baseRecord({ method }));
    chainBatch(docs, null);

    docs.forEach((doc, index) => {
      const { stored, recomputed } = selfVerify(doc);
      expect({
        verb: AUDIT_HTTP_METHODS[index],
        methodInDb: stored.method,
        same: recomputed === stored.hash,
      }).toEqual({
        verb: AUDIT_HTTP_METHODS[index],
        methodInDb: AUDIT_HTTP_METHODS[index],
        same: true,
      });
    });
  });

  it('闸必须发生在算哈希之前：chainBatch 之后内存里的 method 与落库一致', () => {
    const docs = [baseRecord({ method: 'CONNECT' })];
    chainBatch(docs, null);
    // 若只在落库侧丢、算哈希侧仍带着 CONNECT，这条记录就永远是红的；
    // 断言「被哈希的对象」自身已不含 method，才说明两侧同源
    expect(docs[0].method).toBeUndefined();
    expect(canonicalPayload(docs[0], CURRENT_PAYLOAD_VERSION)).toBe(
      canonicalPayload({ ...docs[0], method: undefined }, CURRENT_PAYLOAD_VERSION)
    );
  });

  it('同一批里混合动词不得互相污染（逐条同源，链尾连续）', () => {
    const docs = [
      baseRecord({ method: 'GET' }),
      baseRecord({ method: 'PROPFIND' }),
      baseRecord({ method: 'POST' }),
    ];
    const tail = chainBatch(docs, null);
    expect(tail).toBe(docs[docs.length - 1].hash);

    for (const doc of docs) expect(selfVerify(doc).same).toBe(true);
    // 链接性同时成立：第二条的 prevHash 必须是第一条的 hash
    expect(docs[1].prevHash).toBe(docs[0].hash);
    expect(docs[2].prevHash).toBe(docs[1].hash);
  });

  it.failing(
    '登记（本批不修）：clientInfo/location 的多余子键同样在铸造时被剥掉 ⇒ 同一类永久假篡改',
    () => {
      // 今天 src 里没有这两个字段的写入者（只有 schema 声明与 payload 清单），
      // 所以这是「潜在面」而非「在跑的路径」；闸一旦有人接上就会复现同一形态。
      // 用 it.failing 钉住：哪天有人开始写 clientInfo 并修好铸造时机，本例会「意外通过」，
      // 逼着来摘标记，而不是等到整库变红才发现。
      const docs = [baseRecord({ clientInfo: { browser: 'x', os: 'y', device: 'z', gps: '1,2' } })];
      chainBatch(docs, null);
      expect(selfVerify(docs[0]).same).toBe(true);
    }
  );
});
