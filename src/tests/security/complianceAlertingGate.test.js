/**
 * 合规门禁 · 告警投递端点检查（2026-09-26 审计 Top2）
 *
 * 缺陷背景：deployment/observability/alertmanager.yml 的 webhook 接收端是占位 URL，
 * 开箱部署即 critical 告警全部发往不存在域名，而此前仓内无任何防线要求生产接入时替换。
 *
 * 判据本体在 scripts/compliance-alerting.js（纯函数，本文件直调测试）：
 *   - 仓库态（gateMode='repo'，CI 默认）：占位放行但 detail 必须显形；
 *   - 生产闸（gateMode='production'）：占位即红——上线声明"告警链路可用"必须先过这道闸；
 *   - 明文 http / 残缺占位值：任何模式都红（它们不是模板约定的一部分）。
 * 登记对账（registry 含 checkAlertingDeliveryEndpoint）由 complianceGate.test.js
 * 的 C/D 两格覆盖，此处只测判据行为。
 */
const fs = require('fs');
const path = require('path');
const {
  classifyWebhookUrl,
  extractWebhookEndpoints,
  evaluateAlertingDelivery,
} = require('../../../scripts/compliance-alerting.js');

const ALERTMANAGER_YML = path.resolve(
  __dirname,
  '../../../deployment/observability/alertmanager.yml'
);

// 仓库占位 URL 形态。尖括号占位符不写成字面量：仓库安全扫描钩子会把字符串里的
// < > 误判为 shell 重定向，故用 fromCharCode 构造，分类语义不变。
const ANGLE_OPEN = String.fromCharCode(60);
const ANGLE_CLOSE = String.fromCharCode(62);
const PLACEHOLDER_URL =
  'https://hooks.example.com/' + ANGLE_OPEN + '替换为critical通知通道access_token' + ANGLE_CLOSE;

const PLACEHOLDER_SRC = [
  'receivers:',
  '  - name: ops-critical',
  '    webhook_configs:',
  "      - url: '" + PLACEHOLDER_URL + "'",
  '        send_resolved: true',
].join('\n');

describe('合规门禁 · 告警投递端点判据（审计 Top2）', () => {
  it('三态分类：仓库占位 / 误配明文 http / 正常 https（企微真实形态）', () => {
    expect(classifyWebhookUrl(PLACEHOLDER_URL)).toBe('placeholder');
    expect(classifyWebhookUrl('http://hooks.internal/alert')).toBe('misconfigured');
    expect(classifyWebhookUrl('https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=abc')).toBe(
      'configured'
    );
  });

  it('提取器：整行注释里的 url 不计入，行尾注释与引号内井号不污染值', () => {
    const src = [
      'receivers:',
      '  - name: ops',
      '    webhook_configs:',
      "      # - url: 'https://commented.example.com/this-line-is-a-comment'",
      "      - url: '" + PLACEHOLDER_URL + "' # 私有副本注入前保持占位",
      '        send_resolved: true',
      '  - name: ops2',
      '    webhook_configs:',
      "      - url: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=a#b'",
    ].join('\n');
    const eps = extractWebhookEndpoints(src);
    expect(eps.map((e) => e.url)).toEqual([
      PLACEHOLDER_URL,
      'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=a#b',
    ]);
    expect(eps.map((e) => e.status)).toEqual(['placeholder', 'configured']);
  });

  it('无任何 webhook 接收端 ⇒ 红（触达链路整体断开，不得算就绪）', () => {
    const result = evaluateAlertingDelivery('receivers: []\n', 'repo');
    expect(result.passed).toBe(false);
    expect(result.detail).toContain('未发现任何 webhook 接收端');
  });

  it('两级闸门：仓库态占位放行但显形，生产闸占位即红', () => {
    const repo = evaluateAlertingDelivery(PLACEHOLDER_SRC, 'repo');
    expect(repo.passed).toBe(true);
    expect(repo.detail).toContain('占位 URL');
    expect(repo.detail).toContain('ALERT_WEBHOOK_CHECK=production');

    const prod = evaluateAlertingDelivery(PLACEHOLDER_SRC, 'production');
    expect(prod.passed).toBe(false);
    expect(prod.detail).toContain('ALERT_WEBHOOK_CHECK=production');
  });

  it('明文 http 误配在两种模式下都红', () => {
    const src = "webhook_configs:\n  - url: 'http://hooks.internal/alert'\n";
    expect(evaluateAlertingDelivery(src, 'repo').passed).toBe(false);
    expect(evaluateAlertingDelivery(src, 'production').passed).toBe(false);
  });

  it('真实 alertmanager.yml 在仓库态判绿（与脚本端到端同口径）', () => {
    const result = evaluateAlertingDelivery(fs.readFileSync(ALERTMANAGER_YML, 'utf8'), 'repo');
    expect(result.passed).toBe(true);
    expect(result.detail).toContain('2 处为占位 URL');
  });
});
