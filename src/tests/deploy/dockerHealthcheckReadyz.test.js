/**
 * 持续 /readyz 探测链路的部署侧契约（2026-10-21）
 *
 * 缺陷本体：readyz_verdict 只在 /readyz 被请求时写入，而生产部署里没有任何
 * 周期性调用者——Docker HEALTHCHECK 打 /health，Prometheus 只抓 /metrics，
 * scripts/deploy.js 仅在发布窗口轮询。后果是持续运行期：
 *   - readyz_verdict 不存在 ⇒ MongoUnavailable（== 0）永远不触发；
 *   - readyz_verdict_age_seconds 为 absent ⇒ ReadinessProbeMissing 对健康实例恒告警。
 *
 * 修复口径：HEALTHCHECK 每个周期**并行**探 /readyz 与 /health，但退出码只由
 * /health 决定。这两件事必须同时钉住，缺一不可：
 *   - 只探 /health（旧形态）⇒ 指标永不产生，监控对「能不能干活」是盲的；
 *   - 用 /readyz 决定退出码 ⇒ Mongo 抖动会把容器判成 unhealthy，
 *     与 utils/healthChecks.js 声明的「存活/就绪语义必须分开」相悖。
 *
 * 判据刻意解析 Dockerfile 的 HEALTHCHECK 指令（含反斜杠续行），而不是断言
 * 某个整行字符串：注释措辞、超时数值都可能调整，但「两个路径都打、退出码取
 * health」是契约。下方另附变异用例，证明这条判据在旧实现上真的会红。
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..', '..');
const DOCKERFILE = path.join(ROOT, 'Dockerfile');

/** 提取 HEALTHCHECK 指令（含 `\` 续行），返回去注释后的指令文本 */
function extractHealthcheck(dockerfileText) {
  const lines = dockerfileText.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if (!/^\s*HEALTHCHECK\b/.test(lines[i])) continue;
    const collected = [lines[i]];
    let j = i;
    while (lines[j].trimEnd().endsWith('\\') && j + 1 < lines.length) {
      j += 1;
      collected.push(lines[j]);
    }
    return collected.join('\n');
  }
  return '';
}

/** 从可能的 shell 包装里取出 `node -e "..."` 中真正执行的脚本 */
function extractNodeScript(healthcheck) {
  const m = /node -e "([\s\S]*?)"\s*$/m.exec(healthcheck);
  return m ? m[1] : healthcheck;
}

const dockerfile = fs.readFileSync(DOCKERFILE, 'utf8');
const healthcheck = extractHealthcheck(dockerfile);
const script = extractNodeScript(healthcheck);

/** 契约判据：探针是否同时请求两个路径，且退出码只看 health */
const probesReadyzAndHealth = (s) => /get\('\/readyz'\)/.test(s) && /get\('\/health'\)/.test(s);
const exitCodeFromLiveness = (s) => /process\.exit\(health===200\?0:1\)/.test(s);

describe('Docker HEALTHCHECK 是持续 /readyz 探测链路', () => {
  test('存在 HEALTHCHECK（不是 NONE，也不是被整段注释掉）', () => {
    expect(healthcheck).toMatch(/^HEALTHCHECK\s+--interval=/m);
    expect(healthcheck).not.toMatch(/HEALTHCHECK\s+NONE/);
  });

  test('每周期同时探测 /readyz 与 /health', () => {
    expect(probesReadyzAndHealth(script)).toBe(true);
  });

  test('退出码只由 /health 决定——Mongo 抖动不得把容器判成不健康', () => {
    expect(exitCodeFromLiveness(script)).toBe(true);
    // 反向断言：不得按 /readyz 的状态码退出（旧修复方案最容易犯的错）
    expect(script).not.toMatch(/ready[a-z]*\s*===\s*200\s*\?\s*0/);
    expect(script).not.toMatch(/process\.exit\(ready/);
  });

  test('两个请求并行发出（Promise.all），而非串行等待两次超时', () => {
    expect(script).toMatch(/Promise\.all\(\[get\('\/readyz'\),get\('\/health'\)\]\)/);
  });

  test('探测间隔不超过 60s（ReadinessProbeMissing 的 300s 陈旧阈值需留足余量）', () => {
    const m = /--interval=(\d+)s/.exec(healthcheck);
    expect(m).not.toBeNull();
    expect(Number(m[1])).toBeGreaterThan(0);
    expect(Number(m[1])).toBeLessThanOrEqual(60);
  });

  describe('判据可失败（变异对照）', () => {
    const OLD_HEALTHCHECK =
      "HEALTHCHECK --interval=30s --timeout=10s CMD node -e \"const http=require('http');" +
      "const r=http.get('http://localhost:3000/health',res=>process.exit(res.statusCode===200?0:1));" +
      "r.on('error',()=>process.exit(1));\"";

    test('旧实现（只打 /health）必须被「探 /readyz」判据拒绝', () => {
      const oldScript = extractNodeScript(OLD_HEALTHCHECK);
      expect(probesReadyzAndHealth(oldScript)).toBe(false);
      expect(exitCodeFromLiveness(oldScript)).toBe(false);
    });

    test('若有人改用 /readyz 决定退出码，必须被「退出码取存活」判据拒绝', () => {
      const bad =
        "const get=p=>p;Promise.all([get('/readyz'),get('/health')]).then(()=>process.exit(ready===200?0:1));";
      expect(probesReadyzAndHealth(bad)).toBe(true);
      expect(exitCodeFromLiveness(bad)).toBe(false);
      expect(bad).toMatch(/process\.exit\(ready/);
    });
  });
});
