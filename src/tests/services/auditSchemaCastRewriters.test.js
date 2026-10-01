const mongoose = require('mongoose');
const { AUDIT_HTTP_METHODS } = require('../../constants/audit');
const { PAYLOAD_FIELDS_V4 } = require('../../utils/auditChainPayload');
const AuditLog = require('../../models/AuditLog');

/**
 * 审计 schema 的「铸造期改写器」登记表。
 *
 * 【缺陷家族】审计有两条写入路径，批量路径（auditBuffer → chainBatch → insertMany）是
 * **先算哈希、后铸造**。于是 schema 里任何在铸造期改写值的选项都会让「被哈希的形态」
 * ≠「落库的形态」，后果不是少一次校验，而是那条记录**永久 hash_mismatch**（假篡改），
 * 并且它自身的完整性保护从此静默失效。`method` 就是这份家族里的一个已修实例（schema 的 `set`
 * 与 `chainBatch` 共用 `auditMethodOrUndefined`），但修掉一个实例不防止下一个人再写第二个——Mongoose 8 的铸造期改写器有四种：
 * `set` / `trim` / `lowercase` / `uppercase`（后三者连 `find` 的查询条件都会被改写），
 * 全都长得像"无害的字符串整理"。
 *
 * 【实测形状（写判据之前先量，不凭印象）】`AuditLog.schema` 上有 41 条路径，其中 6 条是
 * 点号叶子（`clientInfo.browser` 等），0 条 Embedded 真子文档；`clientInfo` / `location` 作为
 * **父路径在 schema.paths 里并不存在**（嵌套对象字面量被 mongoose 摊平），而它们两个确实进了
 * 哈希载荷。⇒ 嵌套**对象字面量**的叶子由 `eachPath` 自己摊平报出，不需要递归；递归分支只为
 * `type: new Schema()` 的 Embedded 保留（实测那种叶子确实不在 eachPath 里、只在 `pat.schema` 上，
 * 而 Embedded 的父路径名会照常出现）。两条路由由下面第一条用例分别证明有牙。
 *
 * 【为什么不直接改成"先铸造、后算哈希"】那是一次性根治，但要同时处理 insertMany 的毒文档与
 * `ordered:false` 语义、`PAYLOAD_SCHEMA_DEFAULTS` 的分工，以及既有把「chainBatch 抛错仍无哈希落库」
 * 钉成期望的用例——属结构性决策，已登记待拍板。在它落地之前，这道登记表是当前唯一的防线。
 */

/** Mongoose 里在铸造期改写值的四种选项（set 是显式函数，后三个是内置改写） */
const CAST_TIME_REWRITE_OPTIONS = ['set', 'trim', 'lowercase', 'uppercase'];

/**
 * 已在批量侧「算哈希之前」镜像处理过的路径。
 * 每一项都必须能在 `src/utils/auditChain.js` 的 `chainBatch` 里找到对应代码，
 * 由下面「接线」那条用例负责证明——不是靠注释自觉。
 */
const MIRRORED_IN_BATCH_PATH = ['ip', 'method', 'userAgent', 'username'];

/** 递归收集 schema 路径；返回 {name, options}，嵌套对象为点号路径，Embedded 走 pat.schema */
function collectPaths(schema, prefix = '', out = []) {
  schema.eachPath((name, pat) => {
    const fullName = prefix ? `${prefix}.${name}` : name;
    out.push({ name: fullName, options: pat.options || {} });
    if (pat.schema) collectPaths(pat.schema, fullName, out);
  });
  return out;
}

/** 该 schema 被扫描到的全部路径名（不筛改写器）——用来证明"可见集"本身 */
function scannedNamesOf(schema) {
  return collectPaths(schema).map((p) => p.name);
}

const rewritersOf = (options) => CAST_TIME_REWRITE_OPTIONS.filter((k) => options[k] !== undefined);
/** 扫出「带铸造期改写器」的路径名，排序后可直接做集合对拍 */
function rewrittenPathsOf(schema) {
  return collectPaths(schema)
    .filter((p) => rewritersOf(p.options).length > 0)
    .map((p) => p.name)
    .sort();
}

const allAuditLogPaths = collectPaths(AuditLog.schema);
const rewriters = rewrittenPathsOf(AuditLog.schema);
const scannedPathNames = new Set(allAuditLogPaths.map((p) => p.name));

describe('审计 schema 的铸造期改写器必须逐条登记并在批量路径镜像处理', () => {
  it('扫描器对四种改写器都有牙，两条路径（摊平叶子 / Embedded 真子文档）都扫得到', () => {
    // 反向前提自证：若 collectPaths/rewritersOf 写错，下一条用例会因为"什么都没扫到"
    // 而与一份同样为空的登记表相等 ⇒ 假绿。这里用一个已知答案的探针 schema。
    const leaf = new mongoose.Schema({ inner: { type: String, trim: true } }, { _id: false });
    const probe = new mongoose.Schema(
      {
        plain: { type: String },
        gated: { type: String, set: (v) => (v === 'X' ? undefined : v) },
        neat: { type: String, trim: true },
        lowered: { type: String, lowercase: true },
        uppered: { type: String, uppercase: true },
        nestedObj: { tagged: { type: String, set: (v) => v }, bare: String },
        embedded: { type: leaf },
      },
      { _id: false }
    );
    const rewritten = rewrittenPathsOf(probe);
    expect(rewritten).toEqual([
      'embedded.inner',
      'gated',
      'lowered',
      'neat',
      'nestedObj.tagged',
      'uppered',
    ]);
    // 没有任何改写器的那两条不能混进来（防判据过宽 ⇒ 任何 String 字段都会被登记）
    expect(rewritten).not.toContain('plain');
    expect(rewritten).not.toContain('nestedObj.bare');
    // 探针自身也要能被"看见"：embedded 这一格作为 Embedded 父路径必须出现在可见集里，
    // 否则上面的结果可能来自一条根本不遍历子文档的捷径。
    expect(scannedNamesOf(probe)).toEqual(
      expect.arrayContaining(['embedded', 'embedded.inner', 'nestedObj.tagged'])
    );
  });

  it('AuditLog 的改写器清单就是登记表本身：新增一格必须先回答批量侧怎么办', () => {
    expect(rewriters).toEqual([...MIRRORED_IN_BATCH_PATH].sort());
  });

  it('覆盖自证：凡进入哈希载荷的字段都在扫描器可见集里', () => {
    expect(PAYLOAD_FIELDS_V4.length).toBeGreaterThan(0);
    // 实测：`clientInfo` / `location` 是载荷字段，但在 schema.paths 里**没有**同名条目
    // （嵌套对象字面量被 mongoose 摊平成 `clientInfo.browser` 这样的叶子）。所以"可见"
    // 有两种形态：本身是被扫到的路径，或作为父路径其叶子被扫到。
    const isScanned = (field) =>
      scannedPathNames.has(field) ||
      scannedPathNames.has(`${field}.$`) ||
      allAuditLogPaths.some((p) => p.name.startsWith(`${field}.`));
    expect(PAYLOAD_FIELDS_V4.filter((f) => !isScanned(f))).toEqual([]);
    // 前缀规则不能变成万能出口：把"靠父路径混进来的"那几条显式钉住，
    // 将来多出一个既不是路径也不是父路径的名字（＝打错的字段）才会红在这里。
    expect(PAYLOAD_FIELDS_V4.filter((f) => !scannedPathNames.has(f)).sort()).toEqual([
      'clientInfo',
      'location',
    ]);
    // 这条不是"防打错字段名"的唯一防线：compliance/auditChain.test.js 里
    // 「v4 的增量是封闭的四个字段」那条已经钉死了清单内容。本条钉的是**另一件事**：
    // 登记表赖以工作的扫描器（collectPaths）看得见全部被哈希的字段——它才是"改写器清单
    // 为空 ⇒ 全绿"这个假绿风险的出口。两条形如 `field` / `field.leaf` 的判据缺一不可：
    // 前者管清单内容，后者管扫描器的覆盖面。
  });

  it('登记表的每一项在 chainBatch 里都有真实对应处理（不是只登记没接线）', () => {
    const fs = require('fs');
    const path = require('path');
    const src = fs.readFileSync(
      path.join(__dirname, '..', '..', '..', 'src', 'utils', 'auditChain.js'),
      'utf8'
    );
    // 剥掉注释再判：本仓已经三次被"注释里写着、代码里没有"骗过
    const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    const batchBody = code.slice(code.indexOf('function chainBatch'));
    for (const name of MIRRORED_IN_BATCH_PATH) {
      expect({ path: name, handled: new RegExp(`doc\\.${name}\\s*=`).test(batchBody) }).toEqual({
        path: name,
        handled: true,
      });
    }
    // 前提自证：登记表被清空时这条不许"因为无项可查而通过"
    expect(MIRRORED_IN_BATCH_PATH.length).toBeGreaterThan(0);
    // 判据反向自证：把登记项换成一个没接线的路径必须为 false
    expect(new RegExp('doc\\.pathNotRewrittenAtAll\\s*=').test(batchBody)).toBe(false);
  });

  it('method 的降级判据与 schema 用的是同一份实现（防止两处各写一遍再漂移）', () => {
    const setFn = AuditLog.schema.path('method').options.set;
    expect(typeof setFn).toBe('function');
    // 枚举内原样、枚举外一律 undefined：这就是 chainBatch 必须镜像的那条规则
    for (const verb of AUDIT_HTTP_METHODS) expect(setFn(verb)).toBe(verb);
    for (const bad of ['TRACE', 'CONNECT', 'FOO', 'get', '', null, undefined, 123]) {
      expect(setFn(bad)).toBeUndefined();
    }
  });

  /**
   * ip 的闸（2026-10-01 第 5 轮补界）与 method 同规，但多一条**幂等**要求：
   * 批量路径是 chainBatch 跑一次 → insertMany 铸造时 schema 的 set 再跑一次，
   * 两次结果不同就会让「被哈希的形态」≠「落库的形态」（实测形状：截断把空格留在尾部，
   * 第二次 trim 会再剪掉一个字符 ⇒ 64 的哈希对上 63 的存储）。
   * 这条比"两处同源"更容易被将来改规则的人踩到，所以单独钉。
   */
  it('ip 的闸与 schema 同源、且幂等（chainBatch 与 insertMany 会各跑一次）', () => {
    const { auditIpOrUndefined, AUDIT_IP_MAX_LENGTH } = require('../../constants/audit');
    expect(AuditLog.schema.path('ip').options.set).toBe(auditIpOrUndefined);

    expect(auditIpOrUndefined('203.0.113.8')).toBe('203.0.113.8');
    expect(auditIpOrUndefined('::ffff:203.0.113.8')).toBe('::ffff:203.0.113.8');
    expect(auditIpOrUndefined(undefined)).toBeUndefined();
    expect(auditIpOrUndefined(null)).toBeUndefined();
    expect(auditIpOrUndefined('')).toBeUndefined();
    // 空格/控制字符单独存在时也降级为"不记这一维"，而不是留下一个可被查询命中的串
    expect(auditIpOrUndefined(' \n\u0000 ')).toBeUndefined();
    expect(auditIpOrUndefined(`203.0.113.9\n\u0000injected`)).toBe('203.0.113.9  injected');

    const overlong = `203.0.113.7${'x'.repeat(4000)}`;
    expect(auditIpOrUndefined(overlong)).toHaveLength(AUDIT_IP_MAX_LENGTH);
    // 非字符串一律"不记这一维"（与 method 的「枚举外不记」同口径）：不能退化成
    // String(value)——那会把一个假地址变成可被查询命中的串。
    expect(auditIpOrUndefined(123)).toBeUndefined();
    expect(auditIpOrUndefined({})).toBeUndefined();
    // 控制字符**替换为空格**而非删除（委托给 utils/helpers 的 stripControlChars）：
    // 删除会把两段文本粘成一个看似合法的 token，`1.2.3.4` + LF + `5.6.7.8` 变成
    // `1.2.3.45.6.7.8` 是造假而不是清洗。断言"不出现两个地址"而非只断言"没有换行"。
    expect(auditIpOrUndefined(`1.2.3.4${String.fromCharCode(10)}5.6.7.8`)).toBe('1.2.3.4 5.6.7.8');

    /** 逐码元扫描孤立代理项（不用正则：本仓 eslint 的 no-control-regex 之外，代理区间写法本身易错） */
    const hasLoneSurrogate = (s) => {
      for (let i = 0; i < s.length; i += 1) {
        const code = s.charCodeAt(i);
        if (code >= 0xd800 && code <= 0xdbff) {
          const next = s.charCodeAt(i + 1);
          if (next >= 0xdc00 && next <= 0xdfff) {
            i += 1;
            continue;
          }
          return true;
        }
        if (code >= 0xdc00 && code <= 0xdfff) return true;
      }
      return false;
    };
    // 截断点落在代理对中间时必须已被归一：半个码元在 UTF-8/BSON 里不存在，落盘时驱动会把它
    // 改成 U+FFFD，而哈希是**内存里**算的 ⇒ 内存形态 ≠ 落库形态 ⇒ 永久假篡改。
    // 委托给 stripControlChars 的核心理由正是它已经处理了这一条
    // （见 tests/utils/auditChainSurrogateArtifact.test.js）。
    const emojiCut = auditIpOrUndefined(`203.0.113.7${'😀'.repeat(40)}`);
    expect(emojiCut.length).toBeLessThanOrEqual(AUDIT_IP_MAX_LENGTH);
    expect(hasLoneSurrogate(emojiCut)).toBe(false);

    // 幂等：一次与两次的结果必须完全相同（含"截断点恰好落在空格上"这一形状）
    for (const input of [
      overlong,
      `203.0.113.7${'x'.repeat(AUDIT_IP_MAX_LENGTH - 12)} y`,
      `  1.2.3.4  `,
      `203.0.113.9${String.fromCharCode(10, 13, 0)}FAKE LOG LINE${String.fromCharCode(10)}${'y'.repeat(300)}`,
      `203.0.113.7${'😀'.repeat(40)}`,
    ]) {
      const once = auditIpOrUndefined(input);
      expect(auditIpOrUndefined(once)).toBe(once);
    }
  });

  /**
   * userAgent 的闸与 ip 出自同一个工厂（`makeAuditTextFieldGate`），只有上界不同。
   * 动机不是"字段太长不好看"：全仓 21 个写入点传的是裸 `req.get('user-agent')`
   * （Node 头部上限 ~16KB），而 `userAgent` 在哈希载荷里——批量路径先算哈希、insertMany
   * 才铸造，少一次镜像就是一条永久 hash_mismatch。
   */
  it('userAgent 的闸与 schema 同源、与 ip 同判据、且幂等', () => {
    const {
      auditUserAgentOrUndefined,
      AUDIT_USER_AGENT_MAX_LENGTH,
      auditIpOrUndefined,
      AUDIT_IP_MAX_LENGTH,
    } = require('../../constants/audit');
    expect(AuditLog.schema.path('userAgent').options.set).toBe(auditUserAgentOrUndefined);

    const real =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';
    expect(auditUserAgentOrUndefined(real)).toBe(real);
    for (const absent of [undefined, null, '', '   ', 123, {}, []]) {
      expect(auditUserAgentOrUndefined(absent)).toBeUndefined();
    }

    // 清洗判据必须与 ip 是同一段实现，否则将来改一处漏一处：给两条闸同一个短输入，
    // 输出逐字符相同（上界差异只在长输入上体现，见下面的截断断言）。
    const noisy = `Bad${String.fromCharCode(10, 0, 13)}UA`;
    expect(auditUserAgentOrUndefined(noisy)).toBe(auditIpOrUndefined(noisy));
    expect(auditUserAgentOrUndefined(noisy)).toBe('Bad   UA');

    const overlong = `M${'a'.repeat(9000)}`;
    expect(auditUserAgentOrUndefined(overlong)).toHaveLength(AUDIT_USER_AGENT_MAX_LENGTH);
    // 反向对照：ip 的上界更紧，同一条长 UA 在两条闸下长度不同 ⇒ "同判据"不等于"同配置"。
    expect(auditIpOrUndefined(overlong)).toHaveLength(AUDIT_IP_MAX_LENGTH);

    for (const input of [
      overlong,
      `Mozilla${'x'.repeat(AUDIT_USER_AGENT_MAX_LENGTH - 12)} y`,
      `  ${real}  `,
      `M${'😀'.repeat(400)}`,
    ]) {
      const once = auditUserAgentOrUndefined(input);
      expect(auditUserAgentOrUndefined(once)).toBe(once);
    }
  });
});
