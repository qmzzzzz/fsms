const { computeFingerprint } = require('../../utils/fingerprint');
const { PAYLOAD_FIELDS_V4 } = require('../../utils/auditChainPayload');

/**
 * 会话指纹的编码必须有单射性（批次 71）。
 *
 * 【缺陷形状】`[ua, lang, enc, seg].join('|')` 里 `|` 既是分隔符又是**攻击者可控字符**：
 * User-Agent / Accept-Language / Accept-Encoding 三个头都可以合法地带 `|`，
 * 于是「字段内容移位」得到同一份 material ⇒ 同一份指纹。
 * `fingerprint` 在 v4 哈希载荷字段里（下面第一条用例把它钉成前提），是审计页
 * 「同一行为人」的关联键，也是 `login_unusual_*` 判定的输入之一，所以后果有两个方向：
 *   ① 伪装：攻击者把自己的头调成受害者指纹（把新会话并进受害者的历史关联里）；
 *   ② 摊薄：每请求插一个 `|` 的变体，把自己摊成无数个"不同行为人"，规避按指纹收口的告警。
 *
 * 【修法与为什么不是 JSON.stringify】material 一改，**存量指纹全部失效**：
 * 审计记录里已落库的 fingerprint 与新写的永不相等，"同一设备"的跨版本关联被切断。
 * 所以只对两个保留字符做转义（`\` → `\\`、`|` → `\|`）：
 * 不含 `|` 与 `\` 的头（绝大多数真实浏览器请求）material 字节不变 ⇒ 指纹不变。
 * 第三条用例把这份连续性钉成黄金值，谁改成整体重编码就会红。
 */

const stub = (ua, lang, enc, ip = '10.1.2.3') => ({
  ip,
  get: (key) =>
    ({ 'user-agent': ua, 'accept-language': lang, 'accept-encoding': enc })[key] ?? undefined,
});

describe('会话指纹的字段边界必须不可伪造', () => {
  it('前提：fingerprint 是哈希载荷字段，关联键被伪造不是纯展示问题', () => {
    expect(PAYLOAD_FIELDS_V4).toContain('fingerprint');
  });

  it('含 | 或 \\ 的头不得因字段移位而合并成同一个指纹', () => {
    // 管道符/空字段移位：朴素 join('|') 下这四组 material 会塌成两两相同（最后一行自证）
    const shifted = [
      ['A|B', 'C', 'gzip'],
      ['A', 'B|C', 'gzip'],
      ['A', 'B', 'C|gzip'],
      ['A|', '', 'x'],
      ['A', '|', 'x'],
    ].map((t) => computeFingerprint(stub(...t)));
    expect(new Set(shifted).size).toBe(shifted.length);

    // 反斜杠必须**一起**转义：穷举实测（zztmpctl/zZbProbeEscapeInjectivity71.js）给出
    // ['\','','|'] 与 ['|','\',''] 这一对——只转义 `|` 时两者 material 同为 `\||\||SEG`，
    // 两个都转义才分开。所以下面这组钉的是"半套转义不算修好"。
    const backslash = [
      ['A\\', 'B', 'gzip'],
      ['A', '\\B', 'gzip'],
      ['\\', '', '|'],
      ['|', '\\', ''],
    ].map((t) => computeFingerprint(stub(...t)));
    expect(new Set(backslash).size).toBe(backslash.length);

    // 判据反向自证：朴素 join 确实把第一组的前两项塌成一串（证明这些靶子选得对）
    const naive = (t) => [...t, '10.1.2'].join('|');
    expect(naive(['A|B', 'C', 'gzip'])).toBe(naive(['A', 'B|C', 'gzip']));
    expect(naive(['A|', '', 'x'])).toBe(naive(['A', '|', 'x']));
  });

  it('不含 | 与 \\ 的头必须维持存量指纹（连续性：不得整体重编码）', () => {
    // 黄金值取自"修复前的朴素 join('|')"实现：常规 UA/lang/enc 的 material 逐字节不变。
    // 若有人换成 JSON.stringify 之类整体重编码，这条必须红，并由人来确认关联断裂可接受。
    const golden = '5a959e4b7310ec93afe1ea60d6f0ba26';
    expect(
      computeFingerprint(
        stub('Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'zh-CN,zh;q=0.9', 'gzip, deflate')
      )
    ).toBe(golden);

    // 反向对照：换 IP 段就换指纹（说明这条黄金值不是常量返回值）
    expect(
      computeFingerprint(
        stub(
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
          'zh-CN,zh;q=0.9',
          'gzip, deflate',
          '10.9.9.9'
        )
      )
    ).not.toBe(golden);
  });

  it('头与网段都取不到时仍然不产出指纹（既有语义不得被转义改动带偏）', () => {
    // seg 参与「全空」判定，所以这里要用一个产不出网段的 IP 才能走到 null 分支
    expect(computeFingerprint(stub('', '', '', 'not-an-ip'))).toBeNull();
    expect(computeFingerprint(null)).toBeNull();
    expect(computeFingerprint({ ip: '10.1.2.3' })).toBeNull();
    // 反向对照：同样的空头 + 可用网段 ⇒ 必须产出指纹（证明上一条的 null 来自判空而非判错）
    expect(computeFingerprint(stub('', '', ''))).toMatch(/^[0-9a-f]{32}$/);
  });
});
