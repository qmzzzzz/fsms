/**
 * 核心旅程压测脚本（E-1）
 *
 * 目标：建立 QPS / P95 / P99 的可复现基线，而不是「感觉不慢」。
 *
 * 运行前置（压测专用环境，勿对生产直接打）：
 *   1. 独立压测库（MONGODB_URI 指向专用实例，避免污染开发/生产数据）
 *   2. LOGIN_CAPTCHA_ENABLED=false（验证码是反自动化机制，压测须关闭）
 *   3. LOGIN_ENCRYPT_STRICT 保持默认不开（k6 不便复刻 ECDH 信封；
 *      压测结论代表「认证之后」的链路容量，加密开销另行单独评估）
 *   4. 造数：足够的设备/告警/巡检数据（建议 ≥10k 条，才能暴露深分页问题）
 *   5. 压测账号：环境变量 K6_USER / K6_PASS（脚本不落盘任何凭据）
 *
 * 运行：
 *   k6 run -e BASE_URL=http://127.0.0.1:3000 scripts/perf/k6-core-journeys.js
 *   k6 run --vus 50 --duration 5m ...   # 按需调压
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:3000';
const USERNAME = __ENV.K6_USER || '';
const PASSWORD = __ENV.K6_PASS || '';

const loginFailures = new Rate('login_failures');
const apiErrors = new Rate('api_errors');
const listLatency = new Trend('list_latency_ms', true);

export const options = {
  scenarios: {
    // 基线：爬坡 → 平台 → 泄压，覆盖「逐渐加压找拐点」的常规需求
    ramping: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '1m', target: 10 },
        { duration: '3m', target: 30 },
        { duration: '1m', target: 0 },
      ],
      gracefulRampDown: '30s',
    },
  },
  thresholds: {
    // 基线阈值是「先有数再收紧」的起点：首轮跑完用实测回填，
    // 之后每次回归只允许持平或更好
    http_req_duration: ['p(95)<500', 'p(99)<1500'],
    login_failures: ['rate<0.01'],
    api_errors: ['rate<0.01'],
    list_latency_ms: ['p(95)<800'],
  },
};

const jarCookies = {};

function login() {
  const res = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({ username: USERNAME, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'POST /auth/login' } }
  );
  const ok = check(res, {
    登录成功: (r) => r.status === 200 || r.status === 201,
  });
  loginFailures.add(!ok);
  return ok;
}

function getJson(path, tag) {
  const res = http.get(`${BASE_URL}${path}`, { tags: { name: tag } });
  const ok = check(res, {
    [`${tag} 2xx`]: (r) => r.status >= 200 && r.status < 300,
  });
  apiErrors.add(!ok);
  listLatency.add(res.timings.duration);
  return res;
}

export default function () {
  group('登录', () => {
    if (!login()) {
      sleep(1);
      return;
    }
  });

  group('核心读路径', () => {
    getJson('/api/auth/me', 'GET /auth/me');
    getJson('/api/devices?page=1&limit=20', 'GET /devices 首页');
    getJson('/api/alarms?page=1&limit=20', 'GET /alarms 首页');
    getJson('/api/inspections?page=1&limit=20', 'GET /inspections 首页');
  });

  group('深分页对照（游标 vs offset）', () => {
    // offset 深页：已知退化点，用于量化游标分页的收益
    getJson('/api/alarms?page=200&limit=20', 'GET /alarms offset 深页');
    // 游标深页：首轮请求拿不到真实游标时，此用例仅验证首页响应形状；
    // 正式基线请在造数后用真实 nextCursor 串联（见 README「游标深潜」节）
  });

  sleep(Math.random() * 2 + 1); // 拟人思考时间，避免把限流当容量测
}

export function handleSummary(data) {
  // 终端摘要 + 机读 JSON 留档（基线对比用）
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  return {
    stdout: JSON.stringify(
      {
        at: stamp,
        http_req_duration: data.metrics.http_req_duration?.values,
        list_latency_ms: data.metrics.list_latency_ms?.values,
        api_errors: data.metrics.api_errors?.values,
        login_failures: data.metrics.login_failures?.values,
      },
      null,
      2
    ),
  };
}
