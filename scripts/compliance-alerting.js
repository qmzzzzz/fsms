/**
 * 告警投递端点就绪度判据（2026-09-26 审计 Top2）
 *
 * 缺陷（审计原文）：deployment/observability/alertmanager.yml 的 webhook 接收端是
 * 占位 URL（https://hooks.example.com/<替换为...>），开箱部署即 critical 告警全部
 * 发往不存在域名，而仓内没有任何步骤/测试要求生产接入时替换——文件头虽写"私有副本
 * 注入"，但没有防线兜住"忘了注入"。
 *
 * 本模块供 scripts/compliance-check.js 的第 8 项检查调用，提供两级闸门：
 *   - 仓库态（CI 默认，gateMode='repo'）：占位 URL 是**声明的模板形态**，放行但
 *     detail 必须显形（占位数 + 生产闸提示），不允许"看起来已就绪"；
 *   - 生产闸（ALERT_WEBHOOK_CHECK=production，gateMode='production'，供部署演练/
 *     上线清单调用）：任一 webhook 仍为占位 ⇒ 红。上线声明"告警链路可用"必须先过这道闸。
 * 误配（明文 http、残缺占位值）在任何一级都是红——它们不是模板约定的一部分。
 *
 * 解析口径（零依赖，不引 js-yaml——它是传递依赖，进门禁会把锁文件变更变成红灯）：
 * 逐行匹配 `url:` 并提取首个引号值。整行注释（行首 #）天然不命中锚定正则；
 * 行尾注释在引号值之后，不会被并入值。若未来 YAML 结构复杂化到本判据不可靠，
 * 应先给 alertmanager 配置补 promtool/amtool 校验，再回来改这里。
 */

/** 逐条 webhook URL 的三态分类：placeholder（仓库模板约定）/ configured / misconfigured */
function classifyWebhookUrl(url) {
  // 仓库占位约定：example.com 域名（alertmanager.yml 内的两个占位都落在此），
  // 或带 <...> 尖括号且明示"待替换"的 URL
  if (/example\.com/i.test(url)) return 'placeholder';
  if (/[<>]/.test(url) && /替换|REPLACE|CHANGEME/i.test(url)) return 'placeholder';
  // 明文 http（告警载荷含主机名/IP，明文外发即泄露面）与非 https 的其他形态一律误配
  if (!/^https:\/\//i.test(url)) return 'misconfigured';
  // 尖括号残缺占位但没写替换标记：既不是约定形态也不是合法 URL
  if (/[<>]/.test(url)) return 'misconfigured';
  return 'configured';
}

/** 从一行 `url:` 右侧文本取出值：优先首个引号段，否则截掉行尾注释后取裸词 */
function readUrlValue(rawText) {
  const quoted = rawText.match(/['"]([^'"]+)['"]/);
  if (quoted) return quoted[1];
  const bare = rawText.split('#')[0];
  return bare.trim();
}

/** 从 YAML 源码提取 receivers.webhook_configs 下的全部 url 值 */
function extractWebhookEndpoints(yamlSource) {
  const endpoints = [];
  // 锚定行首：整行注释（行首可选空白后紧跟 #）不命中；
  // `- url:` 与缩进的 `url:` 两种写法都收
  for (const line of yamlSource.split(/\r?\n/)) {
    const hit = line.match(/^[ \t]*-?[ \t]*url:[ \t]*(.+)$/);
    if (!hit) continue;
    const value = readUrlValue(hit[1]);
    if (value) endpoints.push({ url: value, status: classifyWebhookUrl(value) });
  }
  return endpoints;
}

/**
 * 纯判据：给定 YAML 源与闸门模式，产出本检查的结论（供测试直调）。
 * @param {string} yamlSource alertmanager.yml 原文
 * @param {'repo'|'production'} gateMode
 * @returns {{passed: boolean, detail: string}}
 */
function evaluateAlertingDelivery(yamlSource, gateMode) {
  const endpoints = extractWebhookEndpoints(yamlSource);
  if (endpoints.length === 0) {
    return {
      passed: false,
      detail:
        'alertmanager.yml 未发现任何 webhook 接收端：告警触达链路整体断开（critical/warning 都将无人收到）',
    };
  }
  const misconfigured = endpoints.filter((e) => e.status === 'misconfigured');
  const placeholders = endpoints.filter((e) => e.status === 'placeholder');
  const configured = endpoints.filter((e) => e.status === 'configured');
  if (misconfigured.length > 0) {
    const badList = misconfigured.map((e) => e.url).join('、');
    return {
      passed: false,
      detail:
        `${misconfigured.length} 处 webhook URL 为误配形态（明文 http / 非约定占位残缺值）：` +
        `${badList}。告警载荷含主机名与 IP，明文外发即泄露面`,
    };
  }
  if (gateMode === 'production' && placeholders.length > 0) {
    return {
      passed: false,
      detail:
        `ALERT_WEBHOOK_CHECK=production：${placeholders.length} 处 webhook 仍为占位 URL，` +
        'critical 告警将发往不存在的通道。请按 alertmanager.yml 文件头注释以私有副本/模板渲染注入真实入口后重跑本检查',
    };
  }
  if (placeholders.length > 0) {
    return {
      passed: true,
      detail:
        `${configured.length} 处已配置，${placeholders.length} 处为占位 URL（仓库模板形态）。` +
        '上线前必须替换为真实通知通道，并以生产闸模式（ALERT_WEBHOOK_CHECK=production）重跑合规检查验证',
    };
  }
  return {
    passed: true,
    detail: `${configured.length} 处 webhook 均为 https 且非占位（生产闸通过）`,
  };
}

module.exports = { classifyWebhookUrl, extractWebhookEndpoints, evaluateAlertingDelivery };
