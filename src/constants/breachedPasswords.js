/**
 * 弱口令**词干**表（G8）
 *
 * ## 这里存的是词干，不是口令字面量
 * 比对在 utils/helpers.isBreachedPassword：口令侧先归一化，再查本表。
 * 归一化 = 小写化 → 去掉**所有**非字母数字（分隔符/符号/空白）→ 去掉**末尾连续数字**。
 * 例：`Admin@123456` → `admin`；`P@ssw0rd1234!` → `pssw0rd`；`Fire@2026Safe!` → `fire2026safe`。
 * 所以本表只写词干（`admin`、`pssw0rd`），**不要**写成 `admin@123` 那种口令字面量。
 *
 * ## 为什么从「口令字面量」改成「词干」（2026-10-09）
 * 旧版是 40 条口令字面量，而旧归一化**只**做「末尾 ≥4 位数字收敛为 3 位」且**只归一化
 * 口令侧**。两者口径不一致的直接后果：实测 40 条里 **24 条永远命中不了**（生产路径上
 * 黑名单比对在长度/复杂度之后，8~11 位的条目先被长度规则拒掉；且「以 ≥4 位数字结尾」
 * 的条目永远不等于任何口令的归一化结果）⇒ **有效字典只有 16 个词干**，而文件看起来有 40 条。
 * 死条目不是数据错，是**匹配器与数据口径不一致**：清单里 `passw0rd!` / `p@ssw0rd` /
 * `1qaz@wsx` / `abcd1234!` 这种写法本身就说明作者意图是「按词干匹配」。
 * 现在表就是词干、归一化只有一份（口令侧），两者不可能再漂移。
 * **不变量：每个词干必须至少含 2 个字母**——只含 1 个字母（或纯数字）的词干无法被任何
 * 「通过策略」的口令命中（策略要求同时含大写与小写，而词干里只有 1 个字母就无法同时满足）。
 * 该不变量由 `src/tests/utils/breachedPasswordMatcher.test.js` 逐条构造反例验证。
 *
 * ## 为什么仍然不接 HaveIBeenPwned（2026-10-09 修正表述）
 * 旧注释写「那会把用户密码哈希前缀发往第三方」——**这句话本身是准确的**，实测 range API
 * 确实只收到 SHA-1 的前 **5 个十六进制字符**（如 `25C2C`），返回约 2000 条候选后缀，
 * 后缀留在本地比对（k-anonymity，k≈1993；`Password@123` 命中 1,763,928 次）。
 * 但原表述**不完整且推论未经论证**：它没写「只有 5 位」、没提 k-anonymity、没提 TLS，
 * 把「发前缀」当成了不证自明的否决理由；而真正有分量的那条理由它没写——
 * **注册/改密链路上多一个运行时外部依赖，以及它不可达时的失败策略**。
 * 故本表保留的理由是后者，不是隐私。若将来要接 HIBP，失败策略**已预先拍板**：
 * **fail-open + 指标 + 启动日志告警**（不可达时放行并留痕，不让第三方可用性拖垮改密链路；
 * 与本仓 securityAlertDelivery 的取向一致），且必须带超时与缓存。
 *
 * ## 能力边界（如实声明）
 * 这是一份**人工维护的高频词干表**，不是撞库字典。它覆盖的是「满足复杂度规则、但位于
 * 所有字典前列」的那一族（`Word@12345` 这类同源变异）；**长尾覆盖不了**——不在本表里的
 * 已泄露口令（如 `MyDog2019!`）只有 HIBP 那一类「真实泄露库」能查到。
 * 2026-10-09 实测口径：186 条「通过策略且未被本表拦截」的构造样本中，HIBP 还能再命中
 * 110 条（59.1%）；把本表按词干匹配后，同一批样本里 `Passw0rd!1234`、`P@ssw0rd1234!`、
 * `Abcd1234!5678`、`1Qaz@Wsx1234!` 等由漏变拦。
 */
const BREACHED_PASSWORD_STEMS = new Set([
  // —— 默认/占位凭据 ——
  'admin',
  'password',
  'passw0rd',
  'pssw0rd',
  'pssword',
  'root',
  'user',
  'test',
  'guest',
  'login',
  'welcome',
  'changeme',
  'secret',
  'master',
  'letmein',
  'access',
  'computer',

  // —— 通用英文词 ——
  'freedom',
  'mustang',
  'killer',
  'matrix',
  'thunder',
  'summer',
  'sunshine',
  'iloveyou',
  'princess',
  'starwars',
  'shadow',
  'dragon',
  'monkey',
  'batman',
  'superman',
  'football',
  'baseball',
  'flower',
  'purple',
  'orange',
  'banana',
  'hunter',
  'soccer',
  'tigger',
  'pepper',
  'ginger',
  'cheese',
  'hockey',
  'ranger',
  'tiger',
  'panda',
  'eagle',

  // —— 常见人名 ——
  'michael',
  'jordan',
  'charlie',
  'robert',
  'thomas',
  'daniel',
  'andrew',
  'jessica',
  'michelle',
  'ashley',
  'nicole',
  'matthew',
  'william',
  'george',
  'joshua',
  'amanda',
  'jennifer',
  'taylor',
  'austin',
  'dallas',
  'hannah',
  'arsenal',
  'chelsea',
  'liverpool',
  'barcelona',
  'juventus',

  // —— 键盘走位与字母序列 ——
  'qwerty',
  'qwertyuiop',
  'qazwsx',
  'asdfgh',
  'zxcvbnm',
  'wsxedc',
  'poiuyt',
  'qweasd',
  '1qaz2wsx',
  '1qazwsx',
  '1q2w3e4r',
  'qwer',
  'zaq1wsx',
  'abc',
  'abcd',
  'abcdef',
  'abcabc',
  'aa',

  // —— 平台与品牌 ——
  'google',
  'samsung',
  'facebook',
  'linkedin',
  'twitter',
  'apple',
  'amazon',
  'microsoft',
  'huawei',
  'xiaomi',
  'taobao',
  'baidu',
  'alibaba',
  'weixin',
  'weibo',
  'pingan',

  // —— 中文拼音（地名 / 本系统）——
  'china',
  'beijing',
  'shanghai',
  'guangzhou',
  'tianjin',
  'chongqing',
  'shenzhen',
  'zhongguo',
  'zhonghua',
  'xiaofang',
  'fire',
  'xf',
  'adminqwe',
  'adminasd',
]);

module.exports = { BREACHED_PASSWORD_STEMS };
